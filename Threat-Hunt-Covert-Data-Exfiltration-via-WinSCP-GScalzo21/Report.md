# Threat Hunt Report: Unauthorized File Transfer via WinSCP  
**Detection of Suspicious WinSCP Activity and Data Exfiltration Attempts**  
**Date:** May 29, 2025  

---

## Scenario  
A security analyst observed suspicious ZIP file creation in a user's Documents directory. Further investigation raised concerns about potential data exfiltration using **WinSCP**—a commonly approved file transfer utility. Although WinSCP is legitimate, its use in combination with automation and non-corporate destinations required further review. This hunt aimed to determine if sensitive data had been exfiltrated and whether command-line scripting was involved.

---

## High-Level WinSCP IoC Discovery Plan  
- Check `DeviceFileEvents` for installation of `WinSCP.exe` and archive creation  
- Check `DeviceProcessEvents` for command-line WinSCP executions  
- Check `DeviceNetworkEvents` for outbound traffic over port 22  
- Look for signs of scripted data exfiltration and post-operation cleanup  

---

## Steps Taken  
- Queried `DeviceFileEvents` and confirmed ZIP archive `client_exports_q2.zip` creation  
- Queried `DeviceProcessEvents` for `/script=` execution tied to `WinSCP.exe`  
- Detected command-line usage of `WinSCP.exe` with `upload_script.txt`  
- Searched `DeviceNetworkEvents` for outbound port 22 activity—**none found**  
- Correlated ZIP creation and command-line execution  
- No evidence of outbound transfer or script file present (potential cleanup)  
- Behavior strongly suggests exfiltration attempt with deleted artifacts  

---

## Chronological Events  
1. ZIP archive `client_exports_q2.zip` created in `Documents\Exports`  
2. WinSCP launched using automation script: `upload_script.txt`  
3. No outbound network traffic recorded (possible blind spot or evasion)  
4. No script file found; evidence suggests cleanup took place  

---

## Summary  
This hunt partially confirmed an attempt to use WinSCP for unauthorized data exfiltration. Although outbound SFTP activity was not captured, the pattern of ZIP creation, command-line automation, and absence of the upload script suggests that an internal user staged sensitive files and attempted transfer. Lack of telemetry for the transfer and script cleanup underscores the importance of closing endpoint logging gaps and monitoring CLI usage for common tools.

---

## Response Taken  
Suspicious activity was confirmed on endpoint `DESKTOP-WIN045`.  
The device was isolated, the user account was disabled, and logs were preserved.  
Security detection rules were updated to flag ZIP + WinSCP CLI usage combinations.  

---

## MDE Tables Referenced  
| Table | Description |
|-------|-------------|
| `DeviceFileEvents` | Detected archive creation and ZIP file deletion |
| `DeviceProcessEvents` | Logged WinSCP execution with script arguments |
| `DeviceNetworkEvents` | No outbound SFTP traffic found (possible evasion or gap) |

---

## Detection Queries  

```kql
DeviceFileEvents
| where FileName endswith ".zip" or FileName endswith ".rar"
| where FolderPath has_any ("Documents", "Downloads", "Desktop")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName
```
<img width="994" alt="Screenshot 2025-05-30 at 10 53 01 PM" src="https://github.com/user-attachments/assets/f03b5dd9-c7b1-475e-a441-dc5b84433721" />



```kql
DeviceProcessEvents
| where FileName == "WinSCP.exe"
| where ProcessCommandLine has "/script"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

```kql
DeviceNetworkEvents
| where RemotePort == 22
| where InitiatingProcessFileName == "WinSCP.exe"
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessAccountName
```

```kql
DeviceFileEvents
| where FileName in~ ("client_exports_q2.zip", "upload_script.txt")
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessAccountName
```

```kql
DeviceFileEvents
| where FileName == "resume_draft2025.docx"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessAccountName
```


<img width="1076" alt="Screenshot 2025-05-30 at 10 57 23 PM" src="https://github.com/user-attachments/assets/25e3f90e-6200-4cb8-b54e-ebb18813139d" />


**Created By:** Giuseppe Scalzo  
**Date:** May 29, 2025  
