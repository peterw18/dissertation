import pandas as pd
import subprocess
from datetime import datetime
import numpy as np
import logging as lg
import math
from sklearn.preprocessing import RobustScaler, MinMaxScaler
from sklearn.pipeline import Pipeline


def stripFormatData(events:pd.DataFrame, logger:lg.Logger) -> pd.DataFrame:
    """
    Removes irrelevant features from the dataset and converts time to standard forms.
    """

    initialFeatures = events.shape[1]

    # get rid of irrelevant features
    try:
        if events.shape[0] > 1:
            events = events.loc[:, events.nunique() > 1].copy()
    except:
        logger.info("Unable to check duplicate columns of a list: of an individual log.")

    SID_COLUMNS = {
        0: 'Security.Identifier.isSystem',
        1: 'Security.Identifier.isAdmin',
        2: 'Security.Identifier.isUnprivileged',
        3: 'Security.Identifier.isLocal',
    }

    try:
        sid_category = events['System.Security.UserID'].map(classifySID)

        events = events.copy().assign(**{
            col: (sid_category == code).astype(int)
            for code, col in SID_COLUMNS.items()
        })

    except KeyError:
        logger.info("Could not find System.Security.UserID feature.")
        for col in SID_COLUMNS.values():
            events.loc[:, col] = 0
        events.loc[:, 'Security.Identifier.isSystem'] = 1
    
    parsedTime = events['System.TimeCreated.SystemTime'].map(
        lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S.%f+00:00")
    )
    hour    = parsedTime.map(lambda dt: dt.hour)
    dow     = parsedTime.map(lambda dt: dt.weekday())
    events['Time.HourOfDay.sin']  = np.sin(2 * np.pi * hour / 24)
    events['Time.HourOfDay.cos']  = np.cos(2 * np.pi * hour / 24)
    events['Time.DayOfWeek.sin']  = np.sin(2 * np.pi * dow  / 7)
    events['Time.DayOfWeek.cos']  = np.cos(2 * np.pi * dow  / 7)

    try:
        events.drop(columns=set(events.filter(like='UserData')).union(events.filter(like='EventData')).union(['System.Provider.EventSourceName', 'System.Provider.Guid', 'System.EventID.Qualifiers', 'System.Version', 'System.Task', 'System.Opcode', 'System.Keywords', 'System.Execution.ThreadID', 'System.Execution.ProcessID', 'System.Computer', 'System.EventID.value', 'System.Security.UserID', 'System.Correlation.ActivityID', 'System.TimeCreated.SystemTime', 'System.Level']), inplace=True, errors='ignore')
    except Exception:
        logger.info("Not all features existed on new log.")
    # logger.info(f"Data stripped and formatted from {initialFeatures} features to {events.shape[1]}.")

    return events

def processLogMessages(logs: str) -> dict:
    logArr = logs.split("\n")[3:]
    logMap = {}

    for line in logArr:
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(" ", 1)
        if len(parts) == 2:
            logMap[parts[0]] = filterLogMessage(parts[1])

    return logMap

def collectLogMessages(events:pd.DataFrame, logger:lg.Logger) -> pd.DataFrame:
    """
    Executes PS command to read actual log messages, and adds them to the dataframe.
    """
    cmd = subprocess.run(
        [
            "powershell", "-Command",
            f"Get-WinEvent -LogName System -MaxEvents {events.shape[0]} "
            f"| Select-Object RecordId, Message "
            f"| Out-String -Width 4096"   # prevent line wrapping
        ],
        capture_output=True,
        text=True
    )
    logger.info("PowerShell command to fetch log messages executed.")

    logMap = processLogMessages(cmd.stdout)
    events['Msg.Text'] = events['System.EventRecordID'].astype(str).map(logMap).fillna("")

    return events


def filterLogMessage(log:str) -> str:
    """
    Removes technical, non-alphabetical details from the log message.
    """
    words = log.split(" ")
    filteredWords = list(filter(lambda x: x.isalpha(), words))

    return " ".join(filteredWords)

def classifySID(sid:str) -> int:
    """
    Splits the Windows Security Identifier into categories: based on privilege.
    """
    if not isinstance(sid, str):
        return 3
    if sid in ["S-1-5-18", "S-1-5-19", "S-1-5-20"]:
        return 0 # system users
    if sid == "S-1-5-32-544" or sid.endswith("-500"):
        return 1 # administrator users
    if sid == "S-1-5-32-545" or sid.endswith("-513"):
        return 2 # standard privilege
    
    return 3 # unknown user account

def ensureScaling(events:pd.DataFrame) -> pd.DataFrame:
    scaler = Pipeline([
        ('robust', RobustScaler()),
        ('minmax', MinMaxScaler())
    ])
    scaler.set_output(transform="pandas")

    return scaler.fit_transform(events)

def aggregateCBOW(vecs:list) -> list:
    """
    Returns metrics on a list of contextualised word embeddings.
    """
    return [np.average(vecs), np.max(vecs), np.min(vecs), np.std(vecs)]

def calculateRunningVals(newValue:float, oldMean:float=None, oldVar:float=None, iters:int=1) -> dict:
    if oldMean is None or  oldVar is None:
        return {
            "mean": newValue,
            "variance": 0,
            "std": 0,
            "iters": 1,
            "z-score": 0.5
        }
    
    runningMean = oldMean + ((newValue - oldMean) / (iters + 1))
    runningVar = oldVar + (newValue - oldMean) * (newValue - runningMean)
    runningStd = math.sqrt(runningVar / (iters + 1))

    return {
            "mean": runningMean,
            "variance": runningVar,
            "std": runningStd,
            "iters": iters + 1,
            "z-score": zscore(newValue, runningMean, runningStd)
    }

def zscore(x:float, mean:float, std:float) -> float:
    return (x - mean) / std if std > 0 else 0.0