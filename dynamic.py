from modules.evtxParser import parseEVTX
from modules.dataProcessor import stripFormatData, collectLogMessages, calculateRunningVals, aggregateCBOW, ensureScaling
from modules.machineLearning import encodeSentences, createHalfSpaceTrees, getHSTPredictions
from modules.algorithmEvaluation import plotHist
from modules.logWatcher import createWatcher
from windows_toasts import Toast, InteractableWindowsToaster, ToastButton, ToastDisplayImage, ToastImage, ToastImagePosition
from pathlib import Path
from river import anomaly
from datetime import datetime, timedelta
import logging as lg
import pandas as pd
import os
import sys
import ctypes
import joblib
import threading
import queue
import subprocess

# ============= LOGGING CONFIG ===============

logger = lg.getLogger(__name__)
logger.setLevel(lg.DEBUG)

os.makedirs(name='logs', exist_ok=True)
file_handler = lg.FileHandler('logs/main.log')
file_handler.setLevel(lg.DEBUG)
file_handler.setFormatter(lg.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

stream_handler = lg.StreamHandler()
stream_handler.setLevel(lg.DEBUG)
stream_handler.setFormatter(lg.Formatter('[*] %(asctime)s - %(message)s', datefmt='%H:%M:%S'))

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# ==============================================

# ============ GLOBAL VARIABLES ================

logFiles = ["C:\\Windows\\System32\\winevt\\Logs\\Application.evtx", "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "C:\\Windows\\System32\\winevt\\Logs\\System.evtx"]

# ==============================================

# ============= CHECK FOR ADMIN ================

def checkIfAdmin() -> bool:
    """
    Checks if the program is running as admin.
    """
    try:
        isAdmin = os.getuid() == 0
    except AttributeError:
        isAdmin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    return isAdmin

# ==============================================

# ============ RENDER CSV TO DF ================

def csv_to_df(filename) -> pd.DataFrame:
    """
    Loads a CSV file from the filesystem to a DataFrame.
    """
    return pd.read_csv(filename, low_memory=False)

# ==============================================

# =========== INCOMING EVENT HANDLER ===========

def receive_event(HST:anomaly.HalfSpaceTrees, event:dict, previousEvents:pd.DataFrame) -> tuple:
    """
    Handles when a new log is received by the watchers.
    """

    formattedEvent = {}

    formattedEvent['Msg.Vectors'] = encodeSentences([event["message"]])
    msg_avg, msg_max, msg_min, msg_std = zip(*map(aggregateCBOW, formattedEvent['Msg.Vectors']))
    
    formattedEvent['Msg.Vectors.Avg'] = msg_avg[0]
    formattedEvent['Msg.Vectors.Max'] = msg_max[0]
    formattedEvent['Msg.Vectors.Min'] = msg_min[0]
    formattedEvent['Msg.Vectors.Std'] = msg_std[0]
    formattedEvent.pop('Msg.Vectors', None)

    formattedEvent['Provider.Vectors'] = encodeSentences([event["provider"]])
    prov_avg, prov_max, prov_min, prov_std = zip(*map(aggregateCBOW, formattedEvent['Provider.Vectors']))
    
    formattedEvent['Provider.Vectors.Avg'] = prov_avg[0]
    formattedEvent['Provider.Vectors.Max'] = prov_max[0]
    formattedEvent['Provider.Vectors.Min'] = prov_min[0]
    formattedEvent['Provider.Vectors.Std'] = prov_std[0]
    formattedEvent.pop('Provider.Vectors', None)


    formattedEvent['System.TimeCreated.SystemTime'] = (datetime.strptime(event["timeGenerated"].split('-')[0], '%Y%m%d%H%M%S.%f') + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S.%f+00:00')
    formattedEvent['System.Security.UserID'] = event["sid"]

    thisEvent = stripFormatData(pd.DataFrame([formattedEvent]), logger)
    thisEvent =ensureScaling(thisEvent)

    eventDict = thisEvent.iloc[0].to_dict()
    thisEvent["anomaly"] = HST.score_one(eventDict)
    thisEvent["originLog"] = event["log"]
    thisEvent['System.EventRecordID'] = event["recordNumber"]
    thisEvent['timeGenerated'] = datetime.strptime(event["timeGenerated"].split('-')[0], '%Y%m%d%H%M%S.%f') + timedelta(hours=1)

    thisEvent = pd.concat([thisEvent, pd.DataFrame([
        calculateRunningVals(
            newValue=thisEvent.iloc[0]["anomaly"],
            oldMean=previousEvents.iloc[-1]["anomaly-mean"],
            oldVar=previousEvents.iloc[-1]["anomaly-variance"],
            iters=previousEvents.iloc[-1]["anomaly-iters"]
    )]).add_prefix("anomaly-")], axis=1)
    
    if abs(thisEvent["anomaly-z-score"].iloc[0]) < 3:
        HST.learn_one(eventDict)

    currentEvents = pd.concat([previousEvents.iloc[1:], thisEvent])

    return HST, currentEvents

# ==============================================

# =================== MAIN =====================

def main():
    """
    The main function for the program. Brings all modular functions together.
    """

    if (not checkIfAdmin()):
        logger.warning(msg="Service running without administrator privileges.")
        sys.exit(10)

    # ======= ESTABLISH BASELINE EVENTS ========

    os.makedirs(name='baseline', exist_ok=True)
    os.makedirs(name='raw', exist_ok=True)
    if not any(Path('baseline').iterdir()):
        logger.info("Baseline events do not exist. Generating...")
            
        for logFile in logFiles:
            logger.info(f"{logFile}: Creating baseline events.")
            filename = "raw/raw-" + logFile.split("\\")[-1] + ".csv"
            if not (Path("raw/raw-" + logFile.split("\\")[-1] + ".csv").exists()):
                parseEVTX(logFile, filename, logger)
            theseEvents = csv_to_df(filename)
            
            theseEvents = collectLogMessages(theseEvents, logger)
            logger.info(f"{logFile}: Collected log messages.")

            theseEvents['Msg.Vectors'] = encodeSentences(theseEvents['Msg.Text'].tolist())
            theseEvents['Msg.Vectors.Avg'], theseEvents['Msg.Vectors.Max'], theseEvents['Msg.Vectors.Min'], theseEvents['Msg.Vectors.Std'] = zip(*theseEvents['Msg.Vectors'].map(aggregateCBOW).tolist())
            theseEvents.drop(columns=['Msg.Text', 'Msg.Vectors'], inplace=True)
            logger.info(f"{logFile}: Encoded log messages.")

            if 'System.Provider.Name' in theseEvents:

                theseEvents['Provider.Vectors'] = encodeSentences(theseEvents['System.Provider.Name'].tolist())
                theseEvents['Provider.Vectors.Avg'], theseEvents['Provider.Vectors.Max'], theseEvents['Provider.Vectors.Min'], theseEvents['Provider.Vectors.Std'] = zip(*theseEvents['Provider.Vectors'].map(aggregateCBOW).tolist())
                theseEvents.drop(columns=['System.Provider.Name', 'Provider.Vectors'], inplace=True)
                logger.info(f"{logFile}: Encoded provider names.")
            
            theseEvents = stripFormatData(theseEvents, logger)
          
            theseEvents = ensureScaling(theseEvents)
            logger.info(f"{logFile}: Scaled log features.")
            
            thisCSV = ".\\baseline\\" + logFile.split("\\")[-1] + ".csv"
            theseEvents.to_csv(thisCSV, index=False)
            logger.info(f"{logFile}: Saved baseline events to {thisCSV}.")
    
    # ==========================================

    # ======== CREATE HALF SPACE TREES =========

    baselineEvents = pd.concat([csv_to_df(file) for file in Path('baseline').glob("*.evtx.csv")], axis=0).sample(frac=1)
    
    os.makedirs(name='models', exist_ok=True)
    if not (Path('models/HalfSpaceTrees.jblb').exists()):
        HSTModel = createHalfSpaceTrees(baselineEvents.iloc[:5000], logger)
        joblib.dump(HSTModel, 'models/HalfSpaceTrees.jblb')
    else:
        HSTModel = joblib.load('models/HalfSpaceTrees.jblb')

    calculatedEvents = getHSTPredictions(baselineEvents.iloc[5000:], HSTModel, logger)
    plotHist(calculatedEvents, 'anomalous', 'HSTRawHistogram')

    # ==========================================

    # ============ COMPUTE Z-SCORE =============

    state = {}
    scores = []

    for _, row in calculatedEvents.iterrows():
        prev = state.get("anomalous")
        if prev:
            vals = calculateRunningVals(
                newValue=row["anomalous"],
                oldMean=prev["mean"],
                oldVar=prev["variance"],
                iters=prev["iters"]
            )
        else:
            vals = calculateRunningVals(newValue=row["anomalous"])
        
        state["anomalous"] = vals
        scores.append(vals)
    
    calculatedEvents = calculatedEvents.reset_index(drop=True)
    calculatedEvents = pd.concat([calculatedEvents, pd.DataFrame(scores).add_prefix("anomaly-")], axis=1)

    plotHist(calculatedEvents, 'anomaly-z-score', 'HSTZScoreHistogram')

    # ==========================================

    input("[!] Ensure network is disabled...")

    # ======== ESTABLISH FILE WATCHERS =========
    
    stopEvent = threading.Event()
    eventQueue = queue.Queue()
    threads = []

    logger.info("Creating event log watchers...")

    for logFile in logFiles:
        thr = threading.Thread(target=createWatcher, args=(logFile.split("\\")[-1].replace(".evtx", ""),stopEvent, eventQueue))
        threads.append(thr)

    for thr in threads:
        thr.start()

    logger.info("Event log watchers created and running. Press `Ctrl+C` to exit.")

    try:
        while True:
            try:
                thisEvent = eventQueue.get(timeout=0.5)
                HSTModel, calculatedEvents = receive_event(HSTModel, thisEvent, calculatedEvents)
                if abs(calculatedEvents.iloc[-1]["anomaly-z-score"]) >= 3:
                    originLog = calculatedEvents.iloc[-1]["originLog"]
                    eventID = int(calculatedEvents.iloc[-1]['System.EventRecordID'])
                    zperc = round((calculatedEvents.iloc[-1]["anomaly-z-score"] / 3) * 100, 1)
                    timeTaken = round((datetime.now() - calculatedEvents.iloc[-1]["timeGenerated"]).total_seconds(), 2)
                    origTime = calculatedEvents.iloc[-1]["timeGenerated"]

                    logger.warning(f'Event {originLog}:{eventID} is flagged as anomalous, with z-score {zperc}%. Processing took {timeTaken} seconds, originally logged at {origTime}.')
                    with open('logs/anomalies.log', 'a') as file:
                        file.writelines(f"{datetime.now().strftime('%H:%M:%S')} - {eventID}: {zperc}% - {timeTaken}s from {origTime}\n")
                    
                    toaster = InteractableWindowsToaster('Event Monitor')

                    toast = Toast()
                    toast.text_fields = [f'Event Anomaly Detected: {originLog}:{eventID}!', f'Anomalous event with Z-score {zperc}% detected. Click to open.']
                    toast.AddImage(ToastDisplayImage(
                        image=ToastImage(imagePath=r'.\\assets\\warning.png'),
                        position=ToastImagePosition.AppLogo
                    ))

                    toast.AddAction(ToastButton('View Event', arguments='view_event'))
                    toast.on_activated = lambda args: subprocess.run(f'eventvwr.msc /c:{originLog} /f:"*[System[(EventRecordID={eventID})]]"', shell=True) if args.arguments == 'view_event' else None
                    toaster.show_toast(toast)

            except queue.Empty:
                continue

    except KeyboardInterrupt:
        stopEvent.set()
        logger.warning("Control flow halted due to user interaction.")
        logger.info("Exiting...")
        joblib.dump(HSTModel, 'models/HalfSpaceTrees.jblb')

    # ==========================================

# ==============================================

if __name__ == "__main__":
    main()