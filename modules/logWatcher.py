import wmi
import threading
import queue
import win32security
import pythoncom

def createWatcher(log:str, stop_event:threading.Event, eventQueue:queue.Queue) -> "wmi.Win32_NTLogEvent":
    pythoncom.CoInitialize()
    
    try:
        instance = wmi.WMI()
        watcher = instance.Win32_NTLogEvent.watch_for(
            notification_type="Creation",
            LogFile=log
        )

        while not stop_event.is_set():
            try:
                event = watcher(timeout_ms=500)
                eventQueue.put({
                    "log": log,
                    "recordNumber": event.RecordNumber,
                    "message": event.Message,
                    "provider": event.SourceName,
                    "timeGenerated": event.TimeGenerated,
                    "sid": get_sid(event.User)
                })
            except wmi.x_wmi_timed_out:
                continue
    finally:
        pythoncom.CoUninitialize()

def get_sid(username):
    if not username:
        return None
    try:
        sid, _, _ = win32security.LookupAccountName(None, username)
        return win32security.ConvertSidToStringSid(sid)
    except Exception:
        return None
    