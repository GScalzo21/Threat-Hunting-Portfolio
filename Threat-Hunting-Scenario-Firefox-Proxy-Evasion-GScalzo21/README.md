# 🚨 Threat Hunting: Firefox Proxy Evasion

## 📌 Threat Event  
**Firefox Profile Tampering to Route Traffic Through Unauthorized Proxy/VPN**

---

## 🎯 Trigger for Threat Hunt  
On May 26, 2025, a **cybersecurity bulletin** warned about the use of Firefox browser settings to **bypass corporate web filters** via proxy tunneling. Around the same time, **unusual behavior** was observed on a user endpoint: high outbound bandwidth with **no corresponding DNS queries**. Management issued a directive to investigate Firefox misuse across all endpoints.

---

## 🧠 Threat Actor Behavior (Steps Taken)

1. Downloads and installs Firefox (if not already present).
2. Modifies Firefox’s `prefs.js` file to route all browser traffic through a SOCKS5 proxy.
3. Example modifications in `prefs.js`:
    ```js
    user_pref("network.proxy.type", 1);
    user_pref("network.proxy.socks", "127.0.0.1");
    user_pref("network.proxy.socks_port", 9050);
    user_pref("network.proxy.socks_remote_dns", true);
    ```
4. Places the modified `prefs.js` in the Firefox profile folder:
    ```
    C:\Users\<USERNAME>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>.default-release\
    ```
5. Uses Firefox to tunnel traffic and bypass DNS/web filter logging.
6. Deletes the modified file after use to hide activity.

---

## 📁 Tables Used for Detection

| Table Name | Purpose | Link |
|------------|---------|------|
| `DeviceFileEvents` | Detects creation/modification/deletion of `prefs.js` in Firefox profiles. | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| `DeviceProcessEvents` | Detects suspicious or non-standard launches of Firefox. | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| `DeviceNetworkEvents` | Detects Firefox network connections through proxy-related ports. | [Docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |

---

## 🔍 Related Queries (KQL)

### 1. Firefox Preference File Being Modified to Use a Proxy
```kql
DeviceFileEvents
| where FileName == "prefs.js"
| where FolderPath has "Firefox\\Profiles"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
```
### 2. Firefox Running While No DNS Queries Are Made (Potential Proxy Use)
```kql
DeviceProcessEvents
| where FileName == "firefox.exe"
| join kind=leftanti (
    DeviceNetworkEvents
    | where Protocol == "DNS"
    | summarize by DeviceName, bin(Timestamp, 5m)
) on DeviceName, Timestamp
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
### 3. Firefox Network Connections Over Known Proxy Ports
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "firefox.exe"
| where RemotePort in (9050, 1080, 8080)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
```

## 👤 Created By

- **Author:** Giuseppe Scalzo  
- **LinkedIn:** [https://www.linkedin.com/in/giuseppe-scalzo-/)  
- **Date:** May 26, 2025

---

## 📝 Additional Notes

This behavior is commonly associated with **insider threat** or **misconfiguration**, allowing users to **bypass corporate monitoring tools**.  
Ensure monitoring of Firefox installations and inspect user profiles for **unexpected proxy settings**.

---

## 📅 Revision History

| Version | Changes       | Date         | Modified By       |
|---------|---------------|--------------|-------------------|
| 1.0     | Initial Draft | May 26, 2025 | Giuseppe Scalzo   |
