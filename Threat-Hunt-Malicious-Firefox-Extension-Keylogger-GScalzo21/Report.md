# 🔍 Threat Hunt Report — Malicious Firefox Extension (Keylogger)

## Detection of Unauthorized Firefox Extension Abuse (Nifty Keylogger)

---

### 📄 Example Scenario

An internal review raised concerns about a potentially malicious browser extension being used to exfiltrate sensitive data via Firefox. While no alerts were triggered, recent zero-day vulnerabilities involving Firefox extensions prompted management to request a targeted threat hunt. The objective was to simulate and detect the installation, behavior, persistence, and network signals of a keylogger-style `.xpi` extension using Defender for Endpoint telemetry.

---

## 🔎 High-Level Keylogger IoC Discovery Plan

- Detect unusual `.xpi` file installations inside Firefox profile directories  
- Identify renamed/deleted Firefox extension folders  
- Investigate Firefox process launches and command-line arguments  
- Look for persistence mechanisms (e.g., shortcuts in startup folders)  
- Inspect suspicious outbound network connections linked to keywords like `"keylogger"`, `"nifty"`, `"formfill"`, etc.

---

## 🧭 Steps Taken

- Queried `DeviceProcessEvents` for Firefox executions  
- Queried `DeviceFileEvents` for suspicious `.xpi` file creation and renaming  
- Queried for renaming of the `prefs.js` file in the Firefox profile  
- Checked for persistence artifacts (e.g., `firefox.lnk` dropped in Startup folder)  
- Queried for outbound network activity matching known keyword indicators  
- Correlated activity across a single lab machine (`cyberdonut`) and documented all timestamps  

---

## 🗂️ Chronological Events

- Firefox launched on `May 26, 2025, 5:26:23 PM` on device `cyberdonut`  
- Simulated extension (`fake@no-exist.org.xpi`) created and renamed shortly after  
- `prefs.js` was renamed during session (potential tampering)  
- Startup persistence attempt logged as `firefox.lnk.lnk` rename event  
- No outbound traffic to suspicious URLs was detected during the hunt window  

---

## ✅ Summary

A simulated malicious Firefox extension was detected on endpoint `cyberdonut`. The `.xpi` file was staged and renamed within the Firefox profile to mimic stealthy installation behavior. The `prefs.js` file was renamed as part of a simulated evasion attempt. Additionally, a shortcut (`firefox.lnk.lnk`) was created to represent persistence via the Windows Startup folder. While no outbound traffic was logged to known suspicious URLs (e.g., `keylogger`, `autokeylog`), the simulated artifacts matched typical behaviors of malicious extensions.

---

## 🚨 Response Taken

- The device `cyberdonut` was isolated from further external interactions for observation  
- Activity was documented for lab review and defensive control tuning  
- Report submitted to management for awareness and policy alignment  
- Recommendations issued to baseline allowed Firefox extensions and monitor profile folders  

---

## 🧾 MDE Tables Referenced

| Name                 | Purpose                                                                 |
|----------------------|-------------------------------------------------------------------------|
| `DeviceFileEvents`   | Detected `.xpi` file installs, file deletions, persistence artifacts    |
| `DeviceProcessEvents`| Tracked Firefox launch and command-line arguments                       |
| `DeviceNetworkEvents`| Analyzed outbound connections from Firefox to suspicious domains/ports  |

---

## 🧪 Detection Queries Used

---

### 🔍 Firefox Launch Events

```kql
DeviceProcessEvents
| where FileName == "firefox.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
<img width="1019" alt="Screenshot 2025-05-26 at 9 24 06 PM" src="https://github.com/user-attachments/assets/0f4d8570-71e0-4859-bc19-cc231a13132e" />


### 📦 Suspicious .xpi File Installations

DeviceFileEvents
```kql
| where FolderPath has "Mozilla\\Firefox\\Profiles"
| where FileName endswith ".xpi"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessCommandLine
```

<img width="1029" alt="Screenshot 2025-05-26 at 9 24 51 PM" src="https://github.com/user-attachments/assets/57e0d1b9-a3b4-4c18-8dcc-c1596cb0c53b" />


### 🛠️ Extension Directory Renamed or Deleted

DeviceFileEvents
```kql
| where FolderPath has "Mozilla\\Firefox\\Profiles"
| where ActionType in ("FileRenamed", "FileDeleted")
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessCommandLine
```

<img width="939" alt="Screenshot 2025-05-26 at 9 26 18 PM" src="https://github.com/user-attachments/assets/b6b1a627-54e1-40dd-abc3-30978ca04341" />


### 🌐 Suspicious Network Activity
DeviceNetworkEvents
```kql
| where InitiatingProcessFileName == "firefox.exe"
| where RemoteIP != "" and isnotempty(RemoteUrl)
| where RemoteUrl has_any ("keylogger", "nifty", "formfill", "dataupload", "track", "autokeylog")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP
```

<img width="1014" alt="Screenshot 2025-05-26 at 9 26 59 PM" src="https://github.com/user-attachments/assets/18fd6eba-e27a-4196-b75b-8d034bcdc28a" />


### 🧱 Persistence via Startup Folder
```kql
DeviceFileEvents
| where FolderPath has "Startup"
| where FileName == "firefox.lnk"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
```

<img width="975" alt="Screenshot 2025-05-26 at 9 30 52 PM" src="https://github.com/user-attachments/assets/07fa36da-5b0a-4dd2-a705-cc217674cf3f" />


---

## 🧑‍💻 Created By

- **Author Name**: [Giuseppe Scalzo](https://www.linkedin.com/in/giuseppe-scalzo-/)
- **Date**: May 26, 2025

---
