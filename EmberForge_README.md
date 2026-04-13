[EmberForge_README.md](https://github.com/user-attachments/files/26661513/EmberForge_README.md)
# EmberForge: Source Leak - Threat Hunt

## Platform: Microsoft Sentinel
## Language: KQL
## Status: Completed

## Overview

A full-scope threat hunt conducted in Microsoft Sentinel investigating a confirmed breach of EmberForge Studios, a game development subsidiary. The attacker compromised a developer workstation through a targeted phishing delivery, escalated privileges, moved laterally to the application server and domain controller, exfiltrated proprietary source code, and established multiple persistence mechanisms.

This investigation covers the complete attack lifecycle from initial access through exfiltration and anti-forensics.

## Scenario

The CISO escalated a suspected breach and tasked me with answering three critical questions:

1. **What was taken?** Determine the scope of data loss for legal breach notification
2. **How far did they get?** Map the full extent of the compromise across all hosts
3. **Can they come back?** Identify all persistence mechanisms to ensure complete remediation

## Environment

| Host | Role | OS |
|------|------|----|
| EC2AMAZ-B9GHHO6 | Developer Workstation | Windows Server 2022 |
| EC2AMAZ-16V3AU4 | Application Server | Windows Server 2022 |
| EC2AMAZ-EEU3IA2 | Domain Controller | Windows Server 2022 |

**Telemetry:** Sysmon + Windows Security events ingested into a custom Sentinel log table (EmberForgeX_CL)

## Attack Chain Summary

```
Phishing Archive (EmberForge_Review.zip)
    └── 7-Zip extraction to Downloads folder
        └── Mounted ISO/VHD (D:\)
            └── rundll32.exe loads review.dll
                └── update.exe dropped to C:\Users\Public
                    ├── C2 callback to cdn.cloud-endpoint.net
                    ├── UAC bypass via fodhelper.exe
                    ├── Process injection: spoolsv.exe (SYSTEM)
                    ├── LSASS credential dump
                    ├── Reconnaissance (net user, net group, nltest)
                    ├── Lateral movement to Server + DC
                    │   ├── certutil download of tools
                    │   ├── Impacket-style remote execution
                    │   └── AnyDesk silent install
                    ├── ntds.dit extraction via vssadmin
                    ├── Backdoor account: svc_backup (Domain Admins)
                    ├── Data exfil: C:\GameDev → MEGA via rclone
                    └── Anti-forensics: wevtutil log clearing
```

## Tools and Skills Demonstrated

- **Microsoft Sentinel** - SIEM log analysis and investigation
- **KQL (Kusto Query Language)** - Custom queries for threat detection across Sysmon and Windows Security events
- **Sysmon Event Analysis** - Process creation (EID 1), network connections (EID 3), CreateRemoteThread (EID 8), file creation (EID 11), DNS queries (EID 22)
- **Windows Security Events** - Failed logons (4625), service installation (7045)
- **MITRE ATT&CK Mapping** - Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration

## MITRE ATT&CK Coverage

| Tactic | Techniques Identified |
|--------|----------------------|
| Initial Access | T1566.001 (Phishing Attachment), T1553.005 (ISO/VHD Bypass) |
| Execution | T1059.001 (PowerShell), T1059.003 (cmd), T1218.011 (rundll32) |
| Persistence | T1053.005 (Scheduled Task), T1136.002 (Domain Account), T1219 (AnyDesk) |
| Privilege Escalation | T1548.002 (UAC Bypass - fodhelper) |
| Defense Evasion | T1055.003 (Process Injection), T1070.001 (Log Clearing) |
| Credential Access | T1003.001 (LSASS Dump), T1003.003 (ntds.dit) |
| Discovery | T1087.002 (Domain Accounts), T1069.002 (Domain Groups), T1016 (Network Config) |
| Lateral Movement | T1021.002 (SMB/Admin Shares), T1569.002 (Service Execution) |
| Collection | T1560.001 (Compress-Archive) |
| Exfiltration | T1567.002 (Exfil to Cloud - MEGA via rclone) |

## Key IOCs

| Type | Value |
|------|-------|
| C2 Domain | cdn.cloud-endpoint.net |
| C2 IP | 104.21.30.237 |
| Staging Server | sync.cloud-endpoint.net:8080 |
| Exfil Destination | mega.nz (66.203.125.15) |
| Attacker Email | jwilson.vhr@proton.me |
| Malware | C:\Users\Public\update.exe |
| Initial Payload | D:\review.dll |
| Backdoor Account | svc_backup |
| Remote Access | AnyDesk (silently installed) |

## Report

The full investigation report with KQL queries, screenshots, and analysis is available here:

**[EmberForge Threat Hunt Report](file:///Users/symone-mariepriester/Downloads/EmberForge-Threat-Hunt-Report%20(1).html)**

## Repository Structure

```
.
├── README.md
├── EmberForge_ThreatHunt_Report.md
└── images/
    ├── q01_noise_filter.png
    ├── q01_compression_results.png
    ├── q06_rclone_network.png
    ├── q07_rclone_creds.png
    ├── q09_certutil.png
    ├── q10_lisa_activity.png
    ├── q13_execution_chain.png
    ├── q14_7zip_extraction.png
    ├── q16_dns_queries.png
    ├── q17_dns_resolved_ip.png
    ├── q18_injection.png
    ├── q21_stable_injection.png
    ├── q22_lsass_dump.png
    ├── q27_net_share.png
    ├── q28_firewall_rule.png
    ├── q29_parent_process.png
    ├── q30_beacon_copy.png
    ├── q31_lolbin_downloads.png
    ├── q32_raw_services.png
    ├── q32_service_names.png
    ├── q32_csv_confirmation.png
    ├── q33_remote_exec.png
    ├── q34_failed_logons.png
    ├── q35_dc_commands.png
    ├── q36_backdoor_account.png
    ├── q38_domain_admins.png
    ├── q39_net_use.png
    ├── q40_schtasks.png
    ├── q42_anydesk_config.png
    └── q43_wevtutil.png
```

Conducted by **Symone-Marie Priester** 
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Symone--Marie%20Priester-0A66C2?logo=linkedin)](https://linkedin.com/in/symone-mariepriester)
[![GitHub](https://img.shields.io/badge/GitHub-Symone--Marie-181717?logo=github)](https://github.com/Symone-Marie)
