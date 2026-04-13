# Threat Event (Unauthorized Tor Usage)
**Unauthorized Tor Browser Installation and Use**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Download the Tor browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-15.0.9.exe /S```
3. Open the Tor browser from the folder on the desktop
4. Connect to Tor and browse a few sites
5. Create a file on the desktop called ```tor-shopping-list.txt```

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting Tor download and installation, as well as the shopping list creation. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of Tor as well as the Tor browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect Tor network activity, specifically tor.exe and firefox.exe making connections over ports used by Tor (9001, 9030, 9050, 9051, 9150, 9151).|

---

## Related Queries:
```kql
// Detect Tor-related file activity for user "symone"
DeviceFileEvents
| where FileName startswith "tor"
| where InitiatingProcessAccountName == "symone"
| where DeviceName == "win11-tor-symon"
| where Timestamp >= datetime(2026-04-13T16:26:17.2611803Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

// Tor Browser being silently installed
DeviceProcessEvents
| where DeviceName == "win11-tor-symon"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
| project DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

// Tor Browser or service was launched
DeviceProcessEvents
| where DeviceName == "win11-tor-symon"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

// Tor Browser is actively creating network connections over known Tor ports
DeviceNetworkEvents
| where DeviceName == "win11-tor-symon"
| where RemotePort in (9001, 9030, 9050, 9051, 9150, 9151)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath

// User shopping list was created
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## Created By:
- **Author Name**: Symone-Marie Priester
- **Author Contact**: https://www.linkedin.com/in/symone-mariepriester/
- **Date**: April 13, 2026

---

## Additional Notes:
- **Device:** win11-tor-symon
- **User Account:** symone
- **Tor Version:** 15.0.9 (portable)
- **OS:** Windows 11

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 13, 2026`  | `Symone-Marie Priester`   |
