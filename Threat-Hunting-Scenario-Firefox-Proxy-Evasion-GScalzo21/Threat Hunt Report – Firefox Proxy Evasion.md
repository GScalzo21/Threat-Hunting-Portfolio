# 🔎 Threat Hunt Report – Firefox Proxy Evasion

---

## 🎯 Threat Scenario

**Name:** Firefox Profile Tampering to Route Traffic Through Unauthorized Proxy  
**Type:** Insider Evasion Technique  
**Date Executed:** May 26, 2025  
**Analyst:** Giuseppe Scalzo  
**System Used:** Cyberdonut (Windows 10 Defender-Onboarded VM)


---

## 🧪 Objective

To determine whether any endpoints have tampered with Firefox’s `prefs.js` configuration to route browser traffic through a SOCKS proxy, bypassing DNS logging and content filtering. The hunt also includes looking for suspicious file creation/deletion such as `cyberdonut.txt`.

---

## 🚨 Trigger for the Hunt

SOC review showed a user machine with high outbound bandwidth and **no DNS resolution logs**. Management requested an internal hunt based on a known Firefox proxy bypass method observed in recent threat intelligence.

---

## 🧰 Data Sources Used

| Table Name | Purpose |
|------------|---------|
| `DeviceFileEvents` | Track creation/modification/deletion of `prefs.js` and `cyberdonut.txt`. |
| `DeviceProcessEvents` | Detect Firefox execution and abnormal command-line arguments. |
| `DeviceNetworkEvents` | Detect outbound traffic from Firefox to proxy-related ports (e.g., 9050). |

---

## 🔍 Hunting Queries

### 1. Detect Modified Firefox Proxy Settings (`prefs.js`)
```kql
DeviceFileEvents
| where FileName == "prefs.js"
| where FolderPath has "Firefox\\Profiles"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
<img width="926" alt="evidence:prefsjs-modified" src="https://github.com/user-attachments/assets/e1d7e517-0d40-4e7d-816d-ea6897f660d8" />


### 2. Firefox Network Activity Over Proxy Ports
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "firefox.exe"
| where RemotePort in (9050, 1080, 8080)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
```
<img width="1026" alt="Screenshot 2025-05-26 at 5 41 22 PM" src="https://github.com/user-attachments/assets/d3da524a-b6aa-4bc1-b703-72238ea6c9fa" />


### 3. Detect Suspicious File Creation & Deletion (cyberdonut.txt)
```kql
DeviceFileEvents
| where FileName == "cyberdonut.txt"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessAccountName
| order by Timestamp desc
```

<img width="974" alt="Screenshot 2025-05-26 at 5 39 23 PM" src="https://github.com/user-attachments/assets/13d55fc9-fe98-4b9d-952c-c94e7763d2ec" />

---

## 🧾 Findings

- `prefs.js` was modified at  
  `C:\Users\Giuseppe\AppData\Roaming\Mozilla\Firefox\Profiles\xxxx.default-release\`  
  on **May 26, 2025**.
- Firefox attempted to initiate outbound connections on **port 9050 (SOCKS5 proxy)**.
- The file **`cyberdonut.txt`** was created on the Desktop, accessed, and deleted within minutes.

---

## ✅ Conclusion

The simulation successfully mimicked a user configuring Firefox to use an **unauthorized proxy**.  
The logs and queries validated that **Microsoft Defender XDR** (or equivalent EDR/SIEM) can identify:

- 🔧 Firefox profile tampering (`prefs.js` modification)  
- 🌐 Proxy usage and suspicious network activity by `firefox.exe`  
- 🗑️ Attempts to hide evidence via deletion of suspicious files  

**No other systems** were flagged using the same queries, suggesting the activity was isolated to the **test/lab environment**.

---

## 📅 Revision History

| Version | Changes                         | Date         | Author          |
|---------|----------------------------------|--------------|-----------------|
| 1.0     | Initial Hunt Execution and Report | May 26, 2025 | Giuseppe Scalzo |

---

## 👤 Analyst Information

- **Name:** Giuseppe Scalzo  
- **LinkedIn:** [https://www.linkedin.com/in/giuseppe-scalzo-] 
