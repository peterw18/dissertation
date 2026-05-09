# Event Monitor Application
This tool was developed by Peter Walker, Cyber Security BSc student at the University of Warwick for his final year dissertation.

## Breakdown

This tool is an evolving, unsupervised approach to anomaly detection using features from Windows Event Logs. It uses Streaming Half-Space Trees to determine what constitutes an anomaly, and analyses Windows Event logs on the host machine to establish a baseline model.

Additionally, notifications are enabled for detected anomalous logs.

## Installation

1. Download the source code

2. Extract the zip file

3. Run in PowerShell:
```powershell

python -m venv .venv
.\.venv\Scripts\Activate
python -m pip install -r requirements.txt
deactivate

```

4. Open a PowerShell with Administrator privileges:
```powershell

.\.venv\Scripts\Activate
python .\dynamic.py

```

---

Please open a GitHub issue for any bugs / feature requests etc.
© Peter Walker
