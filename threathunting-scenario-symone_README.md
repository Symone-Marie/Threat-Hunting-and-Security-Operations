# Threat Hunt Report: Unauthorized Tor Browser Usage

<img width="400" src="https://upload.wikimedia.org/wikipedia/commons/thumb/1/15/Tor-logo-2011-flat.svg/1200px-Tor-logo-2011-flat.svg.png" alt="Tor Browser Logo"/>

## Platforms and Languages Leveraged
- Windows 11 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

Management suspects that some employees may be using Tor browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known Tor entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any Tor usage and analyze related security incidents to mitigate potential risks. If any use of Tor is found, notify management.

### High-Level Tor-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known Tor ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "symone" downloaded a Tor installer, did something that resulted in many Tor-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-04-13T17:03:07Z`. These events began at `2026-04-13T16:26:17.2611803Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where InitiatingProcessAccountName == "symone"
| where DeviceName == "win11-tor-symon"
| where Timestamp >= datetime(2026-04-13T16:26:17.2611803Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

![DeviceFileEvents Results](screenshots/tor-file-events.png)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.9.exe". Based on the logs returned, at `2026-04-13T16:26:21.0168431Z`, the user "symone" on the "win11-tor-symon" device ran the file `tor-browser-windows-x86_64-portable-15.0.9.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "win11-tor-symon"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
| project DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

![DeviceProcessEvents Results](screenshots/tor-install-events.png)

---

### 3. Searched the `DeviceProcessEvents` Table for Tor Browser Execution

Searched for any indication that user "symone" actually opened the Tor browser. There was evidence that they did open it at `2026-04-13T16:41:24Z`. There were several other instances of `firefox.exe` (Tor) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "win11-tor-symon"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

![DeviceProcessEvents Tor Launch](screenshots/tor-process-events.png)

---

### 4. Searched the `DeviceNetworkEvents` Table for Tor Network Connections

Searched for any indication the Tor browser was used to establish a connection using any of the known Tor ports. At `2026-04-13T16:43:33Z`, the user "symone" on the "win11-tor-symon" device successfully established a connection to the remote IP address `185.244.129.163` on port `9001`. The connection was initiated by the process `tor.exe`, located at `c:\users\symone\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections as well, including one to `51.89.242.29` on port `9001`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "win11-tor-symon"
| where RemotePort in (9001, 9030, 9050, 9051, 9150, 9151)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```

![DeviceNetworkEvents Results](screenshots/tor-network-events.png)

---

## Chronological Event Timeline

### 1. File Download - Tor Installer

- **Timestamp:** `2026-04-13T16:26:17.2611803Z`
- **Event:** The user "symone" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.9.exe` to the Downloads folder.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Symone\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe`

### 2. Process Execution - Silent Installation

- **Timestamp:** `2026-04-13T16:26:21.0168431Z`
- **Event:** The user "symone" executed the file `tor-browser-windows-x86_64-portable-15.0.9.exe` in silent mode, initiating a background installation of the Tor Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.9.exe /S`
- **File Path:** `C:\Users\Symone\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe`

### 3. File Creation - Tor Browser Extracted to Desktop

- **Timestamp:** `2026-04-13T16:36:29Z` - `2026-04-13T16:36:35Z`
- **Event:** The Tor Browser installation extracted multiple files to the Desktop, including `tor.exe`, license files, and a desktop shortcut (`Tor Browser.lnk`).
- **Action:** File creation detected.
- **File Path:** `C:\Users\Symone\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Process Execution - Tor Browser Launch

- **Timestamp:** `2026-04-13T16:41:24Z`
- **Event:** User "symone" opened the Tor Browser. Subsequent processes associated with the Tor Browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of Tor browser-related executables detected.
- **File Path:** `C:\Users\Symone\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Network Connection - Tor Network

- **Timestamp:** `2026-04-13T16:43:33Z`
- **Event:** A network connection to IP `185.244.129.163` on port `9001` by user "symone" was established using `tor.exe`, confirming Tor browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\symone\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 6. Additional Network Connections - Tor Browser Activity

- **Timestamps:**
  - `2026-04-13T16:43:34Z` - Connected to `185.244.129.163` on port `9001` (URL: `https://www.ps7dhii4lsjinvhla.com`).
  - `2026-04-13T16:44:03Z` - Connected to `51.89.242.29` on port `9001` (URL: `https://www.ezqjon7eux4clx.com`).
  - `2026-04-13T16:44:08Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional Tor network connections were established, indicating ongoing activity through the Tor browser.
- **Action:** Multiple successful connections detected.

### 7. File Creation - Tor Shopping List

- **Timestamp:** `2026-04-13T17:03:07Z`
- **Event:** The user "symone" created a file named `tor-shopping-list.txt` on the Desktop, potentially indicating a list or notes related to their Tor browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Symone\Desktop\tor-shopping-list.txt`

---

## Summary

The user "symone" on the "win11-tor-symon" device initiated and completed the installation of the Tor Browser using a silent installation flag (`/S`). They proceeded to launch the browser, establish connections within the Tor network to multiple relay nodes (`185.244.129.163` and `51.89.242.29` on port `9001`), and created various files related to Tor on their Desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the Tor Browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

Tor usage was confirmed on the endpoint `win11-tor-symon` by the user `symone`. The device was isolated, and the user's direct manager was notified.

---
