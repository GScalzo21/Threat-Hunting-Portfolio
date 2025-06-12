# 🕵️‍♂️ Threat Hunt Scenario: Detection of Unauthorized or Malicious Firefox Extensions

## 📌 Summary

This threat hunt report outlines the detection strategy for identifying unauthorized or malicious Firefox browser extensions across enterprise devices. Given the recent discovery of multiple zero-day vulnerabilities affecting third-party Firefox extensions, this hunt proactively examines suspicious browser behaviors, persistence mechanisms, and potential indicators of compromise (IoCs) within endpoint telemetry logs.

---

## 🚨 Threat Event

- **Title:** Use of Unauthorized or Malicious Firefox Extensions  
- **Alternate Label:** Malicious Firefox Extension Abuse  
- **Date Initiated:** May 26, 2025  

---

## 🧠 Reason for Threat Hunt

This hunt was initiated following credible cybersecurity reports detailing zero-day vulnerabilities in various third-party Firefox extensions. These vulnerabilities allow for privilege escalation, unauthorized data access, and potential exfiltration. In response, management requested a proactive investigation to identify suspicious Firefox extension activity across all endpoints.

---

## 🦠 Adversary Behavior Summary

### Simulated Attacker Activity & Logging Footprint

1. Opened Firefox browser
2. Navigated to `addons.mozilla.org` and searched for obscure or suspicious third-party extensions
3. Installed an unverified extension named **"Nifty Keylogger"** by an unknown developer
4. The extension silently began capturing user inputs, such as typed fields and passwords
5. Captured data was exfiltrated to external servers via periodic background requests
6. The attacker attempted to evade detection by:
   - Renaming the extension’s directory
   - Clearing browser history
7. Firefox was added to the Windows Startup folder to maintain persistence
8. User resumed normal browsing while the keylogger operated silently in the background

---

## 🔎 Detection Methodology

This hunt leverages Microsoft Defender for Endpoint telemetry tables to identify key indicators:

| Table Name           | Purpose |
|----------------------|---------|
| `DeviceProcessEvents` | Detect Firefox usage, extension interaction, and startup configuration |
| `DeviceFileEvents`    | Detect creation, renaming, and deletion of `.xpi` extension files or folders |
| `DeviceNetworkEvents` | Detect suspicious outbound connections from Firefox to external servers |

---

## 🧪 Related KQL Queries

### 🔸 [1] Firefox Browser Launch Events
```kql
DeviceProcessEvents
| where FileName == "firefox.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
### 🔸 [2] Suspicious Extension Installations (.xpi Files)
```kql
DeviceFileEvents
| where FolderPath has "Mozilla\\Firefox\\Profiles"
| where FileName endswith ".xpi"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessCommandLine
```
### 🔸 [3] Extension Directory Being Renamed or Deleted
```kql
DeviceFileEvents
| where FolderPath has "Mozilla\\Firefox\\Profiles"
| where ActionType in ("FileRenamed", "FileDeleted")
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessCommandLine
```
### 🔸 [4] Suspicious Network Activity from Firefox
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "firefox.exe"
| where RemoteIP != "" and isnotempty(RemoteUrl)
| where RemoteUrl has_any ("keylogger", "nifty", "formfill", "dataupload", "track", "autokeylog")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP
```
### 🔸 [5] Persistence via Startup Folder
```kql
DeviceFileEvents
| where FolderPath has "Startup"
| where FileName == "firefox.lnk"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
```
## 📝 Additional Notes

- ⚠️ **Whitelist Known Good Extensions**  
  Maintain a baseline of approved extensions within the organization to avoid unnecessary alerts.

- 📁 **Watch for Abnormal Folder Paths or File Hashes**  
  Focus on extension folders with randomized names or abnormal timestamps.

- 🔁 **Correlate File and Network Activity**  
  High-confidence detection often requires tying together file creation/modification with suspicious outbound connections.

- 🧩 **Consider Enrichment with MITRE ATT&CK Mapping**  
  - T1059 – Command & Scripting Interpreter  
  - T1547 – Boot or Logon Autostart Execution  
  - T1212 – Exploitation for Credential Access

## 🧑‍💻 Created By

**Author Name**: [Giuseppe Scalzo](https://www.linkedin.com/in/giuseppe-scalzo-/)  
**Date**: May 27, 2025

---

## 🔍 Validation

*Reviewer Name*:  
*Review Date*:  

---

## 📜 Revision History

| **Version** | **Changes**     | **Date**    | **Modified By**    |
|-------------|------------------|-------------|---------------------|
| 1.0         | Initial Draft    | May 27, 2025    | Giuseppe Scalzo     |
