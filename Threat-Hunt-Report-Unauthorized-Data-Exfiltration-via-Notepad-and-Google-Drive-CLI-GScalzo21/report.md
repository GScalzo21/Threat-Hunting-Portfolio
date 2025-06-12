# 🛡️ Threat Hunt Report (Insider Threat – Covert CLI Exfiltration via Google Drive)

## Detection of Unauthorized CLI-Based Data Exfiltration Using Portable Apps

---

### 📘 Example Scenario
Security operations flagged unusual outbound traffic patterns to a public file storage endpoint and noticed gaps in endpoint logging. Meanwhile, endpoint monitoring reported a ZIP file containing HR documents being created and deleted within minutes. This led to an internal investigation into the potential misuse of command-line interfaces and portable applications for stealthy data exfiltration.

---

### 🔍 High-Level Insider Threat Discovery Plan

- Check `DeviceFileEvents` for signs of ZIP creation and file staging in high-risk folders  
- Check `DeviceProcessEvents` for any executions of `gdrive.exe`, Notepad++ portable, or batch scripts  
- Correlate `DeviceNetworkEvents` for abnormal upload activity to `drive.google.com`  
- Investigate file deletion events that follow shortly after ZIP creation and network exfiltration  

---

### 🔧 Steps Taken

- Queried `DeviceFileEvents` for creation of `confidential_pack.zip` and staged folders in user directories  
- Queried `DeviceProcessEvents` for executions of `gdrive.exe`, `npp.exe`, and scripted uploads  
- Cross-referenced timestamps of ZIP creation with network upload activity  
- Tracked evidence of post-transfer deletions and decoy file creation  
- Investigated installation or unpacking of portable Notepad++ and CLI upload tools  
- Built an event timeline to confirm insider intent and data transfer  

---

### 🗂️ Chronological Events

- Portable Notepad++ extracted to desktop and launched  
- Sensitive HR data staged inside `Performance_Review_Q2` folder  
- Folder compressed into `confidential_pack.zip`  
- ZIP uploaded using `gdrive.exe` to a personal Google Drive account  
- Files, folder, and CLI tools deleted post-transfer  
- Decoy file `Q2_PlanningNotes.txt` created to mislead investigation  

---

### ✅ Summary

This threat hunt uncovered the use of legitimate tools in an illegitimate way. A portable text editor and command-line Google Drive uploader were used to quietly exfiltrate sensitive company data. While the tools themselves are not inherently malicious, their combination with ZIP compression, timed deletions, and scripted uploads created a behavioral pattern of insider abuse. It highlights the need to monitor command-line utilities and portable apps—even those commonly used.

---

### 🚨 Response Taken

- Data exfiltration confirmed on endpoint `WORKSTATION-112`  
- The endpoint was **isolated** from the network immediately  
- User account was **disabled pending HR and legal investigation**  
- Artifact collection and full disk forensic image were performed  
- Policies updated to **block unauthorized CLI upload tools** and **flag ZIP creations from sensitive folders**  

---

### 📊 MDE Tables Referenced

| Parameter             | Description                                                                                   |
|-----------------------|-----------------------------------------------------------------------------------------------|
| `DeviceFileEvents`    | Detected staging folder, ZIP file creation, and post-transfer deletion                        |
| `DeviceProcessEvents` | Tracked execution of portable Notepad++ and CLI upload tool (`gdrive.exe`)                    |
| `DeviceNetworkEvents` | Detected outbound HTTP/S uploads to `drive.google.com`                                        |

---

### 🧠 Detection Queries

```kql
// Detect ZIP/RAR creation
DeviceFileEvents
| where FileName == "confidential_pack.zip"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```

```kql
// Detect use of CLI upload tool
DeviceFileEvents
| where FolderPath has "Performance_Review_Q2"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName
```

<img width="992" alt="Screenshot 2025-05-31 at 10 41 22 PM" src="https://github.com/user-attachments/assets/adc5ed82-e531-4dad-9887-bab35659ec50" />

```kql
// Detect portable Notepad++ execution
DeviceProcessEvents
| where FileName == "gdrive.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessParentFileName
```

```kql
// Detect post-transfer file deletions
DeviceNetworkEvents
| where RemoteUrl has "drive.google.com" or RemoteUrl has "googleapis"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
```

<img width="1011" alt="Screenshot 2025-05-31 at 10 44 33 PM" src="https://github.com/user-attachments/assets/64260eb0-4f56-46c5-abd9-da959a05c79e" />


```kql
// Detect uploads to Google Drive
DeviceFileEvents
| where FileName == "Q2_PlanningNotes.txt"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
---

### ✍️ Created By  
**Author:** Giuseppe Scalzo  
**Date:** June 1, 2025  

---

### 📝 Additional Notes  
All actions were documented, and a hunt template was added to the internal SOC playbook to proactively detect future use of command-line upload tools.
