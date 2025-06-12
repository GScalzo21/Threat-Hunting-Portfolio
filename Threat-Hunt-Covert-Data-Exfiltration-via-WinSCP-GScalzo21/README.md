#  🔍 Threat Hunt  — Covert Data Exfiltration via WinSCP

## Detection of Unauthorized File Transfers Using WinSCP

### 🧪 Example Scenario
An insider threat actor attempts to exfiltrate sensitive company data using a common file transfer tool, **WinSCP**, by uploading documents to a personal SFTP server. Because WinSCP is often used legitimately by IT teams, this activity may go unnoticed unless behavior deviates from standard usage patterns.

---

## 🔎 High-Level Insider Threat Discovery Plan

- Detect the download and installation of `WinSCP.exe`
- Look for command-line executions of `WinSCP.exe` using stored sessions or command scripts
- Monitor for file access of sensitive documents (e.g., *.pdf, *.xlsx, *.docx)
- Detect outbound connections to unknown or personal SFTP endpoints (port 22)
- Track unusual bulk file activity and compressed file creation before transfer

---

## 🧭 Steps Taken

- Queried `DeviceProcessEvents` for command-line executions of `WinSCP.exe`
- Queried `DeviceFileEvents` for creation of ZIP/RAR archives and file access in sensitive directories
- Queried `DeviceNetworkEvents` for outbound SFTP traffic
- Correlated event timestamps with account behavior to identify suspicious exfiltration patterns
- Checked for evidence of session log files or saved WinSCP session credentials
- Documented timeline of events and behavior artifacts

---

## 🗂️ Chronological Events

- WinSCP downloaded and installed silently using `WinSCP-6.1.2-Setup.exe /SILENT`
- Large ZIP file `client_exports_q2.zip` created in `Documents\Exports`
- `WinSCP.exe` executed with command line script to upload file via SFTP:  
  `WinSCP.exe /script=upload_script.txt`
- Outbound connection made to `myfilestransfer.ddns.net` over port 22
- Transfer succeeded; session logs cleared after activity

---

## ✅ Summary

This scenario uncovered the use of WinSCP for unauthorized data transfer. Although WinSCP is a legitimate tool, the command-line execution with scripted automation, creation of a large archive, and connections to unknown external hosts indicated malicious intent. This highlights the risk posed by insiders using “approved” tools in unauthorized ways.

---

## 🚨 Response Taken

- The endpoint `WORKSTATION-045` was isolated
- The user account was disabled and investigated
- Session logs and file hashes were preserved for legal review
- Policy updated to monitor command-line execution of file transfer tools

---

## 🧾 Tables Used to Detect IoCs

| Table                | Purpose                                                                 |
|----------------------|-------------------------------------------------------------------------|
| `DeviceProcessEvents` | Detected WinSCP execution and command-line arguments                    |
| `DeviceFileEvents`    | Tracked creation of ZIP files and access to sensitive files             |
| `DeviceNetworkEvents` | Identified outbound SFTP connections                                   |

---

## 🧠 Related Queries

```kusto
// Detect download or install of WinSCP
DeviceFileEvents
| where FileName has "WinSCP"

// Detect WinSCP execution with script
DeviceProcessEvents
| where FileName == "WinSCP.exe"
| where ProcessCommandLine has "/script"
| project Timestamp, DeviceName, FileName, ProcessCommandLine

// Detect creation of ZIP archives in sensitive directories
DeviceFileEvents
| where FileName endswith ".zip" or FileName endswith ".rar"
| where FolderPath has_any ("Documents\\Exports", "Downloads", "Desktop")
| project Timestamp, FileName, FolderPath, ActionType

// Detect outbound SFTP connections
DeviceNetworkEvents
| where RemotePort == 22
| where InitiatingProcessFileName == "WinSCP.exe"
| project Timestamp, RemoteIP, InitiatingProcessAccountName
```
---

**Created By**  
Giuseppe Scalzo  

**Date**  
May 29, 2025  
