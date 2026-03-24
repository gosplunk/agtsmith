# Splunk IOC Detection & Threat Intelligence Guide

---
tags: [splunk, ioc, threat-hunting, mitre-attack, threat-intelligence, security, detection]
category: security
last_updated: 2026-02-20
related_docs: [security_correlation_searches.md, escu_correlation_searches.md, bot_prompts_ioc_threat_hunting.md]
---

**Purpose:** Comprehensive guide for detecting Indicators of Compromise (IOC) and threat hunting using Splunk
**Coverage:** MITRE ATT&CK techniques, threat intelligence, and IOC detection strategies

## Data Sources

- **Attack Data**: 1115 documents
- **AlienVault OTX**: 261 documents
- **Cisco XDR**: 146 documents
- **Total**: 1522 documents

---

<!-- CHUNK: Part 1 - MITRE ATT&CK Detection Techniques -->
# Part 1: MITRE ATT&CK Detection Techniques

Detection strategies organized by MITRE ATT&CK technique ID.

## Technique Index

- [T1003](#t1003)
- [T1003.001](#t1003001)
- [T1003.002](#t1003002)
- [T1003.003](#t1003003)
- [T1003.004](#t1003004)
- [T1003.006](#t1003006)
- [T1003.008](#t1003008)
- [T1005](#t1005)
- [T1007](#t1007)
- [T1014](#t1014)
- [T1016](#t1016)
- [T1018](#t1018)
- [T1020](#t1020)
- [T1021](#t1021)
- [T1021.001](#t1021001)
- [T1021.002](#t1021002)
- [T1021.003](#t1021003)
- [T1021.004](#t1021004)
- [T1021.006](#t1021006)
- [T1027](#t1027)
- [T1027.010](#t1027010)
- [T1027.011](#t1027011)
- [T1027.013](#t1027013)
- [T1030](#t1030)
- [T1033](#t1033)
- [T1035.009](#t1035009)
- [T1036](#t1036)
- [T1036.002](#t1036002)
- [T1036.003](#t1036003)
- [T1036.005](#t1036005)
- [T1036.009](#t1036009)
- [T1037.001](#t1037001)
- [T1040](#t1040)
- [T1041](#t1041)
- [T1046](#t1046)
- [T1047](#t1047)
- [T1048](#t1048)
- [T1048.003](#t1048003)
- [T1049](#t1049)
- [T1053](#t1053)
- [T1053.002](#t1053002)
- [T1053.003](#t1053003)
- [T1053.005](#t1053005)
- [T1053.006](#t1053006)
- [T1053.007](#t1053007)
- [T1055](#t1055)
- [T1055.001](#t1055001)
- [T1057](#t1057)
- [T1059](#t1059)
- [T1059.001](#t1059001)
- [T1059.002](#t1059002)
- [T1059.003](#t1059003)
- [T1059.004](#t1059004)
- [T1059.005](#t1059005)
- [T1068](#t1068)
- [T1069.001](#t1069001)
- [T1069.002](#t1069002)
- [T1070](#t1070)
- [T1070.001](#t1070001)
- [T1070.003](#t1070003)
- [T1070.004](#t1070004)
- [T1070.005](#t1070005)
- [T1071.002](#t1071002)
- [T1071.004](#t1071004)
- [T1072](#t1072)
- [T1078](#t1078)
- [T1078.002](#t1078002)
- [T1078.004](#t1078004)
- [T1082](#t1082)
- [T1083](#t1083)
- [T1087](#t1087)
- [T1087.001](#t1087001)
- [T1087.002](#t1087002)
- [T1087.004](#t1087004)
- [T1090.001](#t1090001)
- [T1090.003](#t1090003)
- [T1095](#t1095)
- [T1098](#t1098)
- [T1098.001](#t1098001)
- [T1098.002](#t1098002)
- [T1098.003](#t1098003)
- [T1098.004](#t1098004)
- [T1098.005](#t1098005)
- [T1102](#t1102)
- [T1102.002](#t1102002)
- [T1105](#t1105)
- [T1110](#t1110)
- [T1110.001](#t1110001)
- [T1110.002](#t1110002)
- [T1110.003](#t1110003)
- [T1110.004](#t1110004)
- [T1112](#t1112)
- [T1113](#t1113)
- [T1114](#t1114)
- [T1114.002](#t1114002)
- [T1114.003](#t1114003)
- [T1115](#t1115)
- [T1119](#t1119)
- [T1127](#t1127)
- [T1127.001](#t1127001)
- [T1129](#t1129)
- [T1133](#t1133)
- [T1134](#t1134)
- [T1134.005](#t1134005)
- [T1135](#t1135)
- [T1136](#t1136)
- [T1136.001](#t1136001)
- [T1136.003](#t1136003)
- [T1140](#t1140)
- [T1176.001](#t1176001)
- [T1185](#t1185)
- [T1187](#t1187)
- [T1189](#t1189)
- [T1190](#t1190)
- [T1195.001](#t1195001)
- [T1195.002](#t1195002)
- [T1197](#t1197)
- [T1199](#t1199)
- [T1200](#t1200)
- [T1201](#t1201)
- [T1202](#t1202)
- [T1204](#t1204)
- [T1204.002](#t1204002)
- [T1204.003](#t1204003)
- [T1207](#t1207)
- [T1212](#t1212)
- [T1213](#t1213)
- [T1213.002](#t1213002)
- [T1216](#t1216)
- [T1218](#t1218)
- [T1218.001](#t1218001)
- [T1218.002](#t1218002)
- [T1218.003](#t1218003)
- [T1218.004](#t1218004)
- [T1218.005](#t1218005)
- [T1218.007](#t1218007)
- [T1218.008](#t1218008)
- [T1218.009](#t1218009)
- [T1218.010](#t1218010)
- [T1218.011](#t1218011)
- [T1218.012](#t1218012)
- [T1218.013](#t1218013)
- [T1219](#t1219)
- [T1220](#t1220)
- [T1222.001](#t1222001)
- [T1222.002](#t1222002)
- [T1482](#t1482)
- [T1484](#t1484)
- [T1484.001](#t1484001)
- [T1484.002](#t1484002)
- [T1485](#t1485)
- [T1486](#t1486)
- [T1489](#t1489)
- [T1490](#t1490)
- [T1496](#t1496)
- [T1497](#t1497)
- [T1497.003](#t1497003)
- [T1498](#t1498)
- [T1499](#t1499)
- [T1505.001](#t1505001)
- [T1505.003](#t1505003)
- [T1505.004](#t1505004)
- [T1505.006](#t1505006)
- [T1525](#t1525)
- [T1526](#t1526)
- [T1528](#t1528)
- [T1529](#t1529)
- [T1530](#t1530)
- [T1531](#t1531)
- [T1537](#t1537)
- [T1539](#t1539)
- [T1542.003](#t1542003)
- [T1543.003](#t1543003)
- [T1546](#t1546)
- [T1546.001](#t1546001)
- [T1546.002](#t1546002)
- [T1546.003](#t1546003)
- [T1546.004](#t1546004)
- [T1546.008](#t1546008)
- [T1546.011](#t1546011)
- [T1546.012](#t1546012)
- [T1546.015](#t1546015)
- [T1547.001](#t1547001)
- [T1547.003](#t1547003)
- [T1547.005](#t1547005)
- [T1547.006](#t1547006)
- [T1547.008](#t1547008)
- [T1547.010](#t1547010)
- [T1547.011](#t1547011)
- [T1547.012](#t1547012)
- [T1548](#t1548)
- [T1548.001](#t1548001)
- [T1548.002](#t1548002)
- [T1548.003](#t1548003)
- [T1550](#t1550)
- [T1550.002](#t1550002)
- [T1550.003](#t1550003)
- [T1552](#t1552)
- [T1552.001](#t1552001)
- [T1552.002](#t1552002)
- [T1552.004](#t1552004)
- [T1552.006](#t1552006)
- [T1552.007](#t1552007)
- [T1553.003](#t1553003)
- [T1553.004](#t1553004)
- [T1553.005](#t1553005)
- [T1554](#t1554)
- [T1555](#t1555)
- [T1555.003](#t1555003)
- [T1555.004](#t1555004)
- [T1555.005](#t1555005)
- [T1556](#t1556)
- [T1556.001](#t1556001)
- [T1556.006](#t1556006)
- [T1557.002](#t1557002)
- [T1558](#t1558)
- [T1558.001](#t1558001)
- [T1558.002](#t1558002)
- [T1558.003](#t1558003)
- [T1558.004](#t1558004)
- [T1559](#t1559)
- [T1560](#t1560)
- [T1560.001](#t1560001)
- [T1561.002](#t1561002)
- [T1562](#t1562)
- [T1562.001](#t1562001)
- [T1562.002](#t1562002)
- [T1562.003](#t1562003)
- [T1562.004](#t1562004)
- [T1562.006](#t1562006)
- [T1562.007](#t1562007)
- [T1562.008](#t1562008)
- [T1562.012](#t1562012)
- [T1563.002](#t1563002)
- [T1564](#t1564)
- [T1564.001](#t1564001)
- [T1564.003](#t1564003)
- [T1564.004](#t1564004)
- [T1564.008](#t1564008)
- [T1565.001](#t1565001)
- [T1566](#t1566)
- [T1566.001](#t1566001)
- [T1566.002](#t1566002)
- [T1567](#t1567)
- [T1567.002](#t1567002)
- [T1569](#t1569)
- [T1569.002](#t1569002)
- [T1570](#t1570)
- [T1572](#t1572)
- [T1574.001](#t1574001)
- [T1574.002](#t1574002)
- [T1574.006](#t1574006)
- [T1574.009](#t1574009)
- [T1574.011](#t1574011)
- [T1578.005](#t1578005)
- [T1580](#t1580)
- [T1584](#t1584)
- [T1585](#t1585)
- [T1586.003](#t1586003)
- [T1587.002](#t1587002)
- [T1587.003](#t1587003)
- [T1588.002](#t1588002)
- [T1589.002](#t1589002)
- [T1590.002](#t1590002)
- [T1590.005](#t1590005)
- [T1595](#t1595)
- [T1598.002](#t1598002)
- [T1601.001](#t1601001)
- [T1611](#t1611)
- [T1620](#t1620)
- [T1621](#t1621)
- [T1647](#t1647)
- [T1649](#t1649)
- [T1654](#t1654)
- [T1673](#t1673)

---

## T1003

**Description:** wdigest regsitry enable datasets.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Credential extraction via DSInternals and PowerSploit modules, as well as CacheDump, FGDump, Lazagne, Mimikatz, native Microsoft debugging tools

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Stanislav Miskovic*

---

## T1003.001

**Description:** Atomic Test Results: Successful Execution of test T1003.001-1 Windows Credential Editor Successful Execution of test T1003.001-2 Dump LSASS.exe Memory using ProcDump Return value unclear for test T1003.001-3 Dump LSASS.exe Memory using comsvcs.dll Successful Execution of test T1003.001-4 Dump LSASS.exe Memory using direct system calls and API unhooking Return value unclear for test T1003.001-6 Offline Credential Theft With Mimikatz Return value unclear for test T1003.001-7 LSASS read with pypykatz

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss, Michael Haag*

---

## T1003.002

**Description:** CVE-2021-36934 exploitation using PowerShell to copy the SAM, SYSTEM and SECURITY hives from a Volume Shadow Copy to a temp folder

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco, Michael Haag*

**Description:** Atomic Test Results: Successful Execution of test T1003.002-1 Registry dump of SAM, creds, and secrets Return value unclear for test T1003.002-2 Registry parse with pypykatz Successful Execution of test T1003.002-3 esentutl.exe SAM copy

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Automatically categorized datasets in directory detect_copy_of_shadowcopy_with_script_block_logging

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

---

## T1003.003

**Description:** Atomic Test Results: Successful Execution of test T1003.003-1 Create Volume Shadow Copy with NTDS.dit Successful Execution of test T1003.003-2 Copy NTDS.dit from Volume Shadow Copy Successful Execution of test T1003.003-3 Dump Active Directory Database with NTDSUtil Successful Execution of test T1003.003-4 Create Volume Shadow Copy with WMI Return value unclear for test T1003.003-5 Create Volume Shadow Copy with Powershell Successful Execution of test T1003.003-6 Create Symlink to Volume Shadow Copy

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1003.004

**Description:** Generated datasets for NoLMHash in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1003.006

**Description:** Manual execution of secretsdump.py to perform a DCSync attack using a domain administrator account & also DC's computer account.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

**Description:** Manual execution of the mimikatz DCSync attack.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

---

## T1003.008

**Description:** Generated datasets for copy file stdoutpipe in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for linux auditd access credential in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Sample of ESXi syslog events showing attempts to access sensitive files on the ESXi system.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## T1005

**Description:** Sample of ESXi syslog events showing downloading of VMs from ESXi using remote tools.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## T1007

**Description:** Generated datasets for net start in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1014

**Description:** Interesting drivers loading on Windows.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Logs from usage of the Medusa rootkit on a Linux host.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## T1016

**Description:** Manual execution of multiple discovery commands.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Generated datasets for linux auditd net tool new in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd net tool in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1018

**Description:** Using PowerView manually to discover systems with unconstrained delegation

**Sourcetypes:** `WinEventLog:Microsoft-Windows-PowerShell/Operational`

### Data Sources
- WinEventLog:Microsoft-Windows-PowerShell/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Microsoft-Windows-PowerShell/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/unconstrained/windows-powershell.log

*Author: Mauricio Velazco*

**Description:** Atomic Test Results: Return value unclear for test T1018-1 Remote System Discovery - net Return value unclear for test T1018-2 Remote System Discovery - net group Domain Computers Return value unclear for test T1018-3 Remote System Discovery - nltest Return value unclear for test T1018-4 Remote System Discovery - ping sweep Return value unclear for test T1018-5 Remote System Discovery - arp Return value unclear for test T1018-8 Remote System Discovery - nslookup Return value unclear for test T1018-9 Remote System Discovery - adidnsdump Return value unclear for test T1018-10 Adfind - Enumerate Active Directory Computer Objects Return value unclear for test T1018-11 Adfind - Enumerate Active Directory Domain Controller Objects

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Jose Hernandez*

**Description:** Using PowerView manually to discover systems with constrained delegation

**Sourcetypes:** `WinEventLog:Microsoft-Windows-PowerShell/Operational`

### Data Sources
- WinEventLog:Microsoft-Windows-PowerShell/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Microsoft-Windows-PowerShell/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/constrained/windows-powershell.log

*Author: Mauricio Velazco*

---

## T1020

**Description:** Generation of rclone activity related to ransomware.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1021

**Description:** Sample of ESXi syslog events showing ESXi shell access being enabled.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

**Description:** Automatically categorized datasets in directory allow_inbound_traffic_in_firewall_rule

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Illegal access to user content via PowerSploit modules, such as access to keyborad logging, audio recording, status of http communications, etc.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021/illegal_access_to_content/logAllPowerSploitModulesWithOldNames.log

*Author: Stanislav Miskovic*

---

## T1021.001

**Description:** Generated datasets for unhide file in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets covering the creation or execution of NirSof ttooling.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

**Description:** Generated datasets for susp default rdp creation in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1021.002

**Description:** Impacket wmiexec execution

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Executable File in SMB File Share

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Atomic Test Results: Return value unclear for test T1021.002-1 Map admin share Successful Execution of test T1021.002-2 Map Admin Share PowerShell Return value unclear for test T1021.002-3 Copy and Execute File with PsExec Return value unclear for test T1021.002-4 Execute command writing output to local Admin Share

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1021.003

**Description:** Manually using the impacket tools to start a process on a remote endpoint leveraging the DCOM protocol for lateral movement and remote code execution.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually using the command line to start a process on a remote endpoint leveraging the DCOM protocol for lateral movement and remote code execution.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually using the command line to start a process on a remote endpoint leveraging the DCOM protocol for lateral movement and remote code execution.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1021.004

**Description:** Simulated lateral movement with SSH

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

**Description:** Sample of ESXi syslog events ssh being enabled on the ESXi system.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## T1021.006

**Description:** Generated datasets for compmgtm access in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Manually using the winrs.exe binary to start a process on a remote endpoint leveraging the WinRM protocol for lateral movement and remote code execution.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually using PowerShell to start an interactive session on a remote endpoint leveraging the WinRM protocol for lateral movement and remote code execution.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1027

**Description:** Atomic Test Results: Successful Execution of test T1027-2 Execute base64-encoded PowerShell Successful Execution of test T1027-3 Execute base64-encoded PowerShell from Windows Registry Return value unclear for test T1027-4 Execution from Compressed File

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Automatically categorized datasets in directory trickbot_drop

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Ran an obfuscated [payload](https://gist.github.com/MHaggis/ccd9848a52dc76e6aa0eb1da14bb7752?permalink_comment_id=4102502#gistcomment-4102502) using FuckThatPacker. These are the raw logs from both Aurora EDR Lite running default logging in json. Also Splunk Windows Universal Forwarder with Windows TA and powershell EventCode 4101 script logging enabled.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Jose Hernandez, Splunk*

---

## T1027.010

**Description:** Generated datasets covering the manual Base64 decoding using PowerShell.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

---

## T1027.011

**Description:** Generated datasets for njrat fileless registry entry in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027.011/njrat_fileless_registry_entry/njrat_registry.log

*Author: Teoderick Contreras, Splunk*

---

## T1027.013

**Description:** Generated datasets for rar sfx execution in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027.013/rar_sfx_execution/rar_sfx.log

*Author: Teoderick Contreras, Splunk*

---

## T1030

**Description:** Generated datasets for linux auditd split syscall new in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd split b exec in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd split syscall in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1033

**Description:** Generated datasets for whoami priv in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd whoami in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Atomic Test Results: Return value unclear for test T1033-1 System Owner/User Discovery Return value unclear for test T1033-3 Find computers where user has session - Stealth mode (PowerView)

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Automated Attack Data Service*

---

## T1035.009

**Description:** Generated datasets for suspicious spawn svchost in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1035.009/suspicious_spawn_svchost/susp_svchost_proc.log

*Author: Teoderick Contreras, Splunk*

---

## T1036

**Description:** Manual create file C:\$Recycle.Bin\test.ps1

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Running sensative processes outside \windows\system32

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/system_process_running_unexpected_location/windows-security.log

*Author: Jose Hernandez*

**Description:** Generated datasets for process temp path in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/process_temp_path/process_temp_path.log

*Author: Teoderick Contreras, Splunk*

---

## T1036.002

**Description:** Manual generation of attack data for right to left override abuse. Simulate outlook attachment and user interaction.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.002/outlook_attachment/rtlo_events.log

*Author: Steven Dick*

---

## T1036.003

**Description:** copy files form system32 or syswow64 folder datasets.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Lou Stella, Splunk*

**Description:** Generated datasets for renamed powershell in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/renamed_powershell/renamed_powershell.log

*Author: Teoderick Contreras, Splunk*

**Description:** Atomic Test Results: Successful Execution of test T1036.003-1 Masquerading as Windows LSASS process Successful Execution of test T1036.003-3 Masquerading - cscript.exe running as notepad.exe Successful Execution of test T1036.003-4 Masquerading - wscript.exe running as svchost.exe Successful Execution of test T1036.003-5 Masquerading - powershell.exe running as taskhostw.exe Return value unclear for test T1036.003-6 Masquerading - non-windows exe running as windows exe Return value unclear for test T1036.003-7 Masquerading - windows exe running as different windows exe Successful Execution of test T1036.003-8 Malicious process Masquerading as LSM.exe Successful Execution of test T1036.003-9 File Extension Masquerading

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1036.005

**Description:** Generated datasets for process in programdata in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.005/process_in_programdata/exec_programdata.log

*Author: Teoderick Contreras, Splunk*

---

## T1036.009

**Description:** Generated datasets for 32bit process execute 64bit in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.009/32bit_process_execute_64bit/32bit_spawn_64bit.log

*Author: Teoderick Contreras, Splunk*

---

## T1037.001

**Description:** Manual generation of attack data for logonscript registry entry for persistence and privilege escalation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1040

**Description:** Splunk TLS/SSL certificate logs

**Sourcetypes:** `stream:tcp`

### Data Sources
- stream:tcp

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: stream:tcp
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1040/ssltls/ssl_splunk.log

*Author: Michael Haag, Splunk*

---

## T1041

**Description:** cisco ios logs

**Sourcetypes:** `bro:ssl:json`

### Data Sources
- bro:ssl:json

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: bro:ssl:json
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1041/zeek_ssl/zeek_ssl.log

*Author: Patrick Bareiss*

---

## T1046

**Description:** Kubernetes scanning activity in Kubernetes audit logs.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Generated datasets for open dns port in attack range.

**Sourcetypes:** `openPorts`

### Data Sources
- openPorts

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: openPorts
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1046/open_dns_port/linux_dns_openports.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for open ports discovery in attack range.

**Sourcetypes:** `openPorts`

### Data Sources
- openPorts

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: openPorts
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1046/open_ports_discovery/linux_known_openports.log

*Author: Teoderick Contreras, Splunk*

---

## T1047

**Description:** Atomic Test Results: Return value unclear for test T1047-1 WMI Reconnaissance Users Return value unclear for test T1047-2 WMI Reconnaissance Processes Return value unclear for test T1047-3 WMI Reconnaissance Software Return value unclear for test T1047-4 WMI Reconnaissance List Remote Services Return value unclear for test T1047-5 WMI Execute Local Process Return value unclear for test T1047-6 WMI Execute Remote Process

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Manually using PowerShell to start a process on a remote endpoint abusing WMI and the Invoke-WmiMethod commandlet for lateral movement and remote code execution.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manual execution of scrcons.exe

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1048

**Description:** ftp connection

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1048.003

**Description:** Manual generation of attack data by generating 100 xls files

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Generated datasets for nslookup exfil in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Manual generation of attack data by browsing to long urls. of Windows.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1049

**Description:** Simulated test Attack range dataset for AD discovery techniques using PoschC2 and a PowerShell implant

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1053

**Description:** Generated datasets for valleyrat schedtask in attack range.

**Sourcetypes:** `XmlWinEventLog:Security`

### Data Sources
- XmlWinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/valleyrat_schedtask/valleyrat_schedtask.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for hidden schedule task in attack range.

**Sourcetypes:** `XmlWinEventLog:Security`

### Data Sources
- XmlWinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/hidden_schedule_task/inno_schtask.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for taskschd dll in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/taskschd_dll/taskschd_dll.log

*Author: Teoderick Contreras, Splunk*

---

## T1053.002

**Description:** Generated datasets for linux new auditd at in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd chown root in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd at in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1053.003

**Description:** Generated datasets for cronjobs entry in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for crontab edit parameter in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for linux auditd cron file audited in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1053.005

**Description:** Automatically categorized datasets in directory svchost_lolbas_execution_process_spawn

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Scheduled Tasks logs captured from Microsoft-Windows-TaskScheduler/Operational.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

**Description:** Manual generation of schtask meant to start as system.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1053.006

**Description:** Generated datasets for linux services restart in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for service systemd in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1053.007

**Description:** Kubernetes audit logs which contains a creation of a cron job.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1055

**Description:** Generated datasets for non-service-searchindexer in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/non-service-searchindexer/seaarch-indexer-non-service.log

*Author: Teoderick Contreras, Splunk*

**Description:** Attack data generation using SliverC2 by BishopFox.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Automatically categorized datasets in directory trickbot_inf

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

---

## T1055.001

**Description:** Testing using DueDLLigence.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1057

**Description:** Generated datasets for process commandline discovery in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1059

**Description:** Sample of ESXi syslog events showing reverse shell attempts from the ESXi system.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

**Description:** Generated datasets for protocol handlers in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/protocol_handlers/protocolhandlers.log

*Author: Michael Haag*

**Description:** Generated datasets for autoit3.exe in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1059.001

**Description:** Manual generation of obfuscated powershell commands using Invoke-Obfuscation

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Manually using Nimplant to execute a PowerShell commandlet using unmanaged PowerShell.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manual generation suspicious PowerShell Exchange modules used in ProxyShell or ProxyNotShell based attacks.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1059.002

**Description:** Generated dataset for amos stealer execution with osquery and endpoint security

**Sourcetypes:** `osquery:results`

### Data Sources
- osquery:results

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: osquery:results
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.002/amos_stealer/amos_stealer.log

*Author: Nasreddine Bencherchali*

---

## T1059.003

**Description:** Manual generation of attack data with a long command line.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/unusally_cmd_line/windows-security.log

*Author: Patrick Bareiss*

**Description:** Manual generation of attack data with a command line arguments.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/cmd_arguments/windows-security.log

*Author: Patrick Bareiss*

**Description:** Atomic Red Team T1059.003

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1059.004

**Description:** Generated datasets for macos lolbin execution with osquery and endpoint security

**Sourcetypes:** `osquery:results`

### Data Sources
- osquery:results

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: osquery:results
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.004/macos_lolbin/osquery.log

*Author: Patrick Bareiss*

**Description:** Generated datasets for linux net discovery in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

---

## T1059.005

**Description:** Manual generation of attack data for txtfile vbs script execution through wscript process.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for discord dnsquery in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1068

**Description:** Simulation of drivers loading up.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael haag*

**Description:** Detection of common behaviors seen during process escalation/elevation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

**Description:** Manual generation of child process of zoom

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1069.001

**Description:** Simulated events with Atomic Red Team and manual.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Generated datasets for njrat admin check in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/njrat_admin_check/win_dat.log

*Author: Teoderick Contreras, Splunk*

---

## T1069.002

**Description:** Automatically categorized datasets in directory domain_group_discovery_with_adsisearcher

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Simulated test Attack range dataset for AD discovery techniques using PoschC2 and a PowerShell implant

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1070

**Description:** Atomic Test Results: Return value unclear for test T1070-1 Indicator Removal using FSUtil

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Automated Attack Data Service*

**Description:** Sample of ESXi syslog events showing manipulation of the system clock.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

**Description:** Generated datasets for rmdir delete files and dir in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070/rmdir_delete_files_and_dir/rmdir.log

*Author: Teoderick Contreras, Splunk*

---

## T1070.001

**Description:** Atomic Test Results: Return value unclear for test T1070.001-1 Clear Logs Successful Execution of test T1070.001-2 Delete System Logs Using Clear-EventLog

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Automatically categorized datasets in directory windows_event_log_cleared

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Automatically categorized datasets in directory suspicious_kerberos_service_ticket_request

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

---

## T1070.003

**Description:** Generated datasets for ConsoleHost History deletion in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.003/ConsoleHost_History_deletion/delete_pwh_history_file.log

*Author: Teoderick Contreras, Splunk*

---

## T1070.004

**Description:** Generated datasets for terminal server reg deleted in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for rdp deletion in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for cipher in attack range.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.004/cipher/security.log

*Author: Teoderick Contreras*

---

## T1070.005

**Description:** Atomic Test Results: Return value unclear for test T1070.005-1 Add Network Share Return value unclear for test T1070.005-2 Remove Network Share Return value unclear for test T1070.005-3 Remove Network Share PowerShell

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Automated Attack Data Service*

---

## T1071.002

**Description:** Outbound smb traffic to another server

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1071.004

**Description:** Generated datasets for vbc dnsquery in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for hugging face in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1072

**Description:** Performing the Death from Above attack moving laterally from Intune management console to an Intune managed device.

**Sourcetypes:** `azure:monitor:activity`

### Data Sources
- azure:monitor:activity

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: azure:monitor:activity
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1072/intune/intune.log

*Author: Dean Luxton*

---

## T1078

**Description:** CloudTrail events where a user A who has already permission to create access keys, makes an API call to create access keys for another user B. Attackers have been know to use this technique for Privilege Escalation in case new victim(user B) has more permissions than old victim(user B)

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

**Description:** Used Invoke-MfaSweep with a valid account against an Azure AD tenant

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manual generation of attack data by enabling DefaultAccount on Windows.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1078.002

**Description:** Manually leverage PowerView to enumerate for active directory access control lists.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Automatically categorized datasets in directory suspicious_computer_account_name_change

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Manual generation of attack data by logging into an account

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_login/windows-security.log

*Author: Lou Stella*

---

## T1078.004

**Description:** This dataset contains an cloudtrail events of successful Console login without MFA

**Sourcetypes:** `aws:cloudtrail`

### Data Sources
- aws:cloudtrail

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudtrail
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/aws_login_sfa/cloudtrail.json

*Author: Bhavin Patel*

**Description:** Used PowerShell to manually authenticate to an Azure AD tenant with an account that does not have Multi Factor authenttication enabled. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Created a forwarding rule programatically using msInvader which triggered an alert by Security & Compliance

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1082

**Description:** Generated datasets for linux auditd lsmod in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd lsmod new in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Atomic Red Team Execution of T1082

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1083

**Description:** Generated datasets for linux auditd find virtual disk in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd find db in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd find document in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1087

**Description:** Generated datasets for powerview get netuser preauthnotrequire in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-PowerShell/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087/powerview_get_netuser_preauthnotrequire/get-netuser-not-require-pwh.log

*Author: Teoderick Contreras, Splunk*

**Description:** Automatically categorized datasets in directory enumerate_users_local_group_using_telegram

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

---

## T1087.001

**Description:** Simulated test Attack range dataset for AD discovery techniques

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1087.002

**Description:** blackmailer ransomware accessing schcache due to creation of adsi object for its ldap query.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Simulated test Attack range dataset for AD discovery techniques

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for adsi discovery in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1087.004

**Description:** This dataset is generated in a AWS Bedrock Lab Environment by simulating events using AWS API calls

**Sourcetypes:** `aws:cloudtrail`

### Data Sources
- aws:cloudtrail

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudtrail
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.004/aws_invoke_model_access_denied/cloudtrail.json

*Author: Bhavin Patel*

**Description:** Detonating AzureHound against Frothly

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

**Description:** This dataset is synthetically generated using by simulating events in a lab

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

---

## T1090.001

**Description:** Generated datasets for netsh portproxy in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1090.003

**Description:** Generated datasets for allowed tor traffic.

**Sourcetypes:** `pan:traffic`

### Data Sources
- pan:traffic

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: pan:traffic
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1090.003/pan_tor_allowed/pan_tor_allowed.log

*Author: Bhavin Patel, Splunk*

---

## T1095

**Description:** Generated datasets for large outbound ICMP using Palo Alto Firewall.

**Sourcetypes:** `pan:traffic`

### Data Sources
- pan:traffic

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: pan:traffic
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1095/palologs/large_icmp.log

*Author: Dean Luxton*

---

## T1098

**Description:** Manually adding a Service Principal Name for a domain admin account account using setspn.exe

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually  enabled a previously disabled account and changed its password within 2 minutes using the Azure portal. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Added a new user to the DnsAdmins active directory group.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1098.001

**Description:** Manually added new client credentials (secret and certificate) for a Service Principal account. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually added new client credentials (secret and certificate) for a Service Principal account. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually created a new API token using the Okta portal. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1098.002

**Description:** Used Exchange Online PowerShell module to grant the ApplicationImpersonation role to a user

**Sourcetypes:** `o365:management:activity`

### Data Sources
- o365:management:activity

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: o365:management:activity
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.002/application_impersonation_role_assigned/application_impersonation_role_assigned.log

*Author: Mauricio Velazco*

**Description:** Added mailbox permissions programatically using msInvader

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually assigned the full_access_as_app API permission to an application registration

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1098.003

**Description:** Manually assigned privileged Azure AD roles to a service principal

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually added granted admin consent to an application registration. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Performing SPN Priviliege escalation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

---

## T1098.004

**Description:** Generated datasets for linux auditd nopasswd in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for ssh authorized keys in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1098.005

**Description:** Enrolled a new device for a user within an Okta tenant. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Added a new MFA method for a user within an Office 365 tenant. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Added a new MFA method for a user within an Azure AD tenant. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1102

**Description:** Generated datasets for njrat ngrok connection in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1102/njrat_ngrok_connection/ngrok.log

*Author: teoderick Contreras, Splunk*

---

## T1102.002

**Description:** Generated datasets for telegram api dns in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1102.002/telegram_api_dns/telegram_dns.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for telegram api requests via command line  in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1102.002/telegram_api_cli/telegram_cli.log

*Author: Nasreddine Bencherchali, Splunk*

---

## T1105

**Description:** Generated datasets for tinyurl dns query in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/tinyurl_dns_query/tinyurl.log

*Author: Teoderick Contreras, Splunk*

**Description:** Successful execution of Atomic Red Team T1105 - Ingress Tool Transfer. Also included Invoke-CertUtil using different command switches.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

**Description:** Generated datasets for dll loaded in temp in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1110

**Description:** Performed a brute force attack against an Okta tenant until accounts were locked out.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco, Splunk*

**Description:** Sample of MFA Sweep events used to enumerate Azure/Entra/o365 MFA weaknesses.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

**Description:** Brute Force Attack O365

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1110.001

**Description:** High Number of Login Failures from a single source O365

**Sourcetypes:** `o365:management:activity`

### Data Sources
- o365:management:activity

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: o365:management:activity
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/high_number_of_login_failures_from_a_single_source/high_number_of_login_failures_from_a_single_source.json

*Author: Bhavin Patel*

**Description:** Dataset which contains cloudtrail events with AWS login failure.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Gowthamaraj Rajendran, Splunk*

**Description:** Used Invoke-MSOLSpray to perform a brute force attack attack against a unique Azure AD account with 25 passwords. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1110.002

**Description:** Dataset which contains cloudtrail events with AWS RDS Database master password reset.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Gowthamaraj Rajendran, Splunk*

---

## T1110.003

**Description:** Automatically categorized datasets in directory purplesharp_disabled_users_kerberos_xml

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Detection of suspicious NTLM authentication behavior.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-NTLM/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-NTLM/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-NTLM/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/ntlm_bruteforce/ntlm_bruteforce.log

*Author: Steven Dick*

**Description:** Used a tool to spray Okta users

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1110.004

**Description:** Manually executed Crackmapexec to spray several endpoints with one combination of username and password using the Administrator account. This dataset contains the failed authentication events for 50+ endpoints.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1112

**Description:** Generated datasets for T1112 in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/disablesecuritysetting.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for kingsoft reg in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/kingsoft_reg/kingsoft_reg.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for bitlocker registry setting in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/bitlocker_registry_setting//fve-reg.log

*Author: Teoderick Contreras, Splunk*

---

## T1113

**Description:** Generated datasets for braodo screenshot in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1113/braodo_screenshot/braodo_screenshot.log

*Author: Teoderick Contreras, Splunk*

---

## T1114

**Description:** Created a forwarding mailflow rule in Office 365 using PowerShell.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Export PST file in O365

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Automatically categorized datasets in directory o365_suspect_email_actions

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

---

## T1114.002

**Description:** Manually accessed O365 emails via Exchange Web Services and an OAuth application registration using a PowerShell script

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually accessed multipla O365 mailboxes using the Graph API and an OAuth application registration using a python script

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Performed full access rights delegation on mailbox in O365.

**Sourcetypes:** `o365:management:activity`

### Data Sources
- o365:management:activity

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: o365:management:activity
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/suspicious_rights_delegation/suspicious_rights_delegation.json

*Author: Patrick Bareiss*

---

## T1114.003

**Description:** Sample of events when an Exchange transport rule is created or modified.

**Sourcetypes:** `o365:management:activity`

### Data Sources
- o365:management:activity

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: o365:management:activity
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.003/transport_rule_change/transport_rule_change.log

*Author: Steven Dick*

**Description:** Created a forwarding rule programatically using msInvader

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Configured forwarding rules for mailboxes in Office 365.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1115

**Description:** Atomic Red Team Execution of T1115

**Sourcetypes:** `sysmon_linux`

### Data Sources
- sysmon_linux

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: sysmon_linux
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1115/atomic_red_team/linux-sysmon.log

*Author: Michael Haag*

**Description:** Generated datasets for linux auditd xclip in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1119

**Description:** Dataset which contains cloudtrail logs for creating a datasync job, batch job creation and bucket replication for AWS exfiltration

**Sourcetypes:** `aws:cloudtrail`

### Data Sources
- aws:cloudtrail

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudtrail
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json

*Author: Bhavin Patel*

**Description:** Generated datasets for doc collection in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1127

**Description:** Microsoft.workflow.compiler.exe usage including renamed and moved.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** etw disable registry datasets.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1127.001

**Description:** MSBuild.exe execution simulating a suspicious spawn, renamed and moved.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** data sets for njrat vbs malware..

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1129

**Description:** Generated datasets for executable shared modules in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1129/executable_shared_modules/image_loaded_exe.log

*Author: Teoderick Contreras, Splunk*

---

## T1133

**Description:** Generated datasets for explorer root proc cmdline in attack range.

**Sourcetypes:** `WinEventLog`

### Data Sources
- WinEventLog

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1133/rdp/terminalservices-rdpclient.log

*Author: Michael Haag, Splunk*

---

## T1134

**Description:** Generated datasets for explorer root proc cmdline in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1134/explorer_root_proc_cmdline/explorer_root.log

*Author: Teoderick Contreras, Splunk*

---

## T1134.005

**Description:** Utilising the sid::patch & sid::add commands from a mimikatz shell running debug privilegs. Successfully patched ntds & added a SID history ad attribute to a user object.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Utilising the sid::patch & sid::add commands from a mimikatz shell running debug privilegs. Successfully patched ntds & added a SID history ad attribute to a user object. Note, also works with computer accounts ;)

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

---

## T1135

**Description:** Manually executed Net Share to discover network file shares in an Active Directory network.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

**Description:** Manually executed PowerSploit's commandlet Invoke-ShareFinder to discover network file shares in an Active Directory network.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually executed PowerSploit's commandlet Invoke-ShareFinder to discover network file shares in an Active Directory network. This dataset contains the Kerberos service ticket requests for 50+ endpoints.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1136

**Description:** Generated datasets for linux unix new user in attack range.

**Sourcetypes:** `syslog`

### Data Sources
- syslog

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: syslog
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136/linux_unix_new_user/linux_new_user.log

*Author: Teoderick Contreras, Splunk*

---

## T1136.001

**Description:** Generated datasets for linux auditd add user type in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd add user in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Atomic Test Results: Return value unclear for test T1136.001-3 Create a new user in a command prompt Successful Execution of test T1136.001-4 Create a new user in PowerShell Successful Execution of test T1136.001-6 Create a new Windows admin user

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1136.003

**Description:** Performed operation Add service principal credentials

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Manually invite External Guest user to the Azure AD. Tenant specific details like tenant id, user names, etc. have been modified.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Gowthamaraj Rajendran*

**Description:** Manually create an Azure Automation account using the Azure Portal. Tenant specific details like tenant id, user names, etc. have been modified.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1140

**Description:** Generated datasets for linux auditd base64 in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Atomic Red Team test results of T1140, certutil.exe decode. Also included Invoke-CertUtil decoding files.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1176.001

**Description:** Generated datasets for disable extension in attack range.

**Sourcetypes:** `XmlWinEventLog:Security`

### Data Sources
- XmlWinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1176.001/disable_extension/iexplore-extoff.log

*Author: Teoderick Contreras, Splunk*

---

## T1185

**Description:** Used Evilnginx3 to phish an O365 user and steal session cookies. Then, imported the stolen session cookies into a different browser to access M365 resources from a different location and source ip. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Used Evilnginx2 to phish an AWS user and steal session cookies , then logged into the console  from attacker machiner while the session from victim machine was also connected.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

**Description:** Used Evilnginx2 to phish an Azure AD user and steal session cookies. Then, imported the stolen session cookies into a different browser to access Azure AD resources from a different location and source ip. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1187

**Description:** Running Petitpotam, ntlmrealy, Rubeus and mimikatz to obtain a TGT as a domain controller and execute a DcSyn attack.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazcom, Michael Haag*

---

## T1189

**Description:** Manual generation of attack data by browsing to dyndns site of Windows.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1190

**Description:** Manual generation of attack data related to ProxyShell.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

**Description:** Manual generation of attack data related to Spring4Shell with Nginx proxy logs

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

**Description:** Manual generation of attack data related to Log4j with network logs

**Sourcetypes:** `stream:ip`

### Data Sources
- stream:ip

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: stream:ip
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/log4j_network_logs/log4j_network_logs.log

*Author: Patrick Bareiss, Splunk*

---

## T1195.001

**Description:** Manual generation of attack data by creating a pull request in GitHub.

**Sourcetypes:** `aws:firehose:json`

### Data Sources
- aws:firehose:json

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:firehose:json
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/github_pull_request/github_pull_request.json

*Author: Patrick Bareiss*

**Description:** Manual generation of attack data by generating security advisor alerts in GitHub.

**Sourcetypes:** `aws:firehose:json`

### Data Sources
- aws:firehose:json

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:firehose:json
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/github_security_advisor_alert/github_security_advisor_alert.json

*Author: Patrick Bareiss*

---

## T1195.002

**Description:** 3CX software running in range

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Manual generation of attack data by disable a workflow in GitHub actions.

**Sourcetypes:** `aws:firehose:json`

### Data Sources
- aws:firehose:json

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:firehose:json
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.002/github_actions_disable_security_workflow/github_actions_disable_security_workflow.log

*Author: Patrick Bareiss*

---

## T1197

**Description:** Execution of Atomic Red Team T1197 - BITS Jobs.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1199

**Description:** Simulated test github Datasets for push or commit in master branch

**Sourcetypes:** `aws:firehose:json`

### Data Sources
- aws:firehose:json

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:firehose:json
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1199/github_push_master/github_push_master.log

*Author: Teoderick Contreras*

---

## T1200

**Description:** Sample of events from executing suspicious files from a recently attached USB drive.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

**Description:** Generated datasets for linux auditd swapoff in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1201

**Description:** Simulated test Attack range dataset for AD Domain Policy Enumeration

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** This dataset is generated in the AWS research tenant by simluating atomic T1201

**Sourcetypes:** `aws:cloudtrail, aws:asl`

### Data Sources
- aws:cloudtrail
- aws:asl

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudtrail, aws:asl
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/aws_password_policy/cloudtrail.json

*Author: Bhavin Patel*

---

## T1202

**Description:** Atomic Test Results: Successful Execution of test T1202 Indirect Command Execution using forfiles.exe and pcalua.exe for evading restructions on process execution.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Eric McGinnis*

---

## T1204

**Description:** Failed login attempt service account AD

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Kubernetes falco logs containing a spawned shell.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Manual generation of attack data by updating a lambda function

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

---

## T1204.002

**Description:** Manual generation of attack data by executing n.exe

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Windows Appx Deployment Server logs

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

**Description:** Manual generation of attack data by playing a bat file in system32 folder of Windows.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1204.003

**Description:** Manual generation of attack data by uploading container to AWS ECR.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Risk events created on Attack range by enabling AWS ECR detections in Dev Sec Ops

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

**Description:** Manual generation of attack data by running aws ecr scanner on docker image in AWS ECR.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1207

**Description:** Manually promoting a server to a Domain Controller.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

**Description:** Manual execution of DCShadow attack using Mimikatz.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manual execution of the mimikatz DCShadow command.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

---

## T1212

**Description:** Manual generation of attack data by running a RFI attack againsta kubernetes cluster with a web app running

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Manual generation of attack data by running a LFI attack againsta kubernetes cluster with a web app running

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1213

**Description:** Splunk Audit Logs.

**Sourcetypes:** `audittrail`

### Data Sources
- audittrail

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: audittrail
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1213/audittrail/audittrail.log

*Author: Mike Haag, Splunk*

---

## T1213.002

**Description:** Sample of events when Sharepoint is searched for a sensitive term / or high rate of searching.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

---

## T1216

**Description:** Atomic Test Results: Successful Execution of test T1216 related to SyncAppvPublishingServer Signed Script PowerShell Command Execution

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1218

**Description:** Risk events related to Living Off The Land Analytic Story

**Sourcetypes:** `stash`

### Data Sources
- stash

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: stash
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Execution of T1218 test 9 in atomic red team

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Lou Stella*

**Description:** Events related to Evil Twin msc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1218.001

**Description:** Invoked AtomicTestHarnesses and executed T1218.001 manually.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1218.002

**Description:** Invoked T1218.002 From Atomic Red Team simulating control.exe behavior

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1218.003

**Description:** Generated datasets for moz lib loaded in attack range.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.003/moz_lib_loaded/mozilla_lib.log

*Author: Teoderick Contreras, Splunk*

---

## T1218.004

**Description:** Simulation of T1218.004 via Atomic Red Team.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1218.005

**Description:** Generated datasets for mshta in registry in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Invoked AtomicTestHarnesses executing T1218.005 manually and via pester tests. Atomic Test Results: Successful Execution of test T1218.005-1 Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject Return value unclear for test T1218.005-2 Mshta executes VBScript to execute malicious command Return value unclear for test T1218.005-3 Mshta Executes Remote HTML Application (HTA) Successful Execution of test T1218.005-4 Invoke HTML Application - Jscript Engine over Local UNC Simulating Lateral Movement Successful Execution of test T1218.005-5 Invoke HTML Application - Jscript Engine Simulating Double Click Successful Execution of test T1218.005-6 Invoke HTML Application - Direct download from URI Successful Execution of test T1218.005-7 Invoke HTML Application - JScript Engine with Rundll32 and Inline Protocol Handler Successful Execution of test T1218.005-8 Invoke HTML Application - JScript Engine with Inline Protocol Handler Successful Execution of test T1218.005-9 Invoke HTML Application - Simulate Lateral Movement over UNC Path

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1218.007

**Description:** Simulation of all procedures from Atomic Red Team.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Generated datasets for msiexec-hidewindow-rundll32 in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/msiexec-hidewindow-rundll32/hidewndw-rundll32.log

*Author: Teoderick Contreras, Splunk*

---

## T1218.008

**Description:** Simulation of all procedures from Atomic Red Team.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1218.009

**Description:** Invoked T1218.009 via AtomicRedTeam and manual execution of regasm and regsvcs.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1218.010

**Description:** Successful execution of Atomic Tests T1218.010 T1218.010-1 Regsvr32 local COM scriptlet execution T1218.010-2 Regsvr32 remote COM scriptlet execution T1218.010-3 Regsvr32 local DLL execution T1218.010-4 Regsvr32 Registering Non DLL Manual execution of same tests, but with moved/renamed regsvr32.exe

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1218.011

**Description:** Generated datasets for rundll32 dll in temp in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Atomic Test Results: Successful Execution of test T1218.011-1 Rundll32 execute JavaScript Remote Payload With GetObject Successful Execution of test T1218.011-2 Rundll32 execute VBscript command Return value unclear for test T1218.011-3 Rundll32 advpack.dll Execution Return value unclear for test T1218.011-4 Rundll32 ieadvpack.dll Execution Return value unclear for test T1218.011-5 Rundll32 syssetup.dll Execution Return value unclear for test T1218.011-6 Rundll32 setupapi.dll Execution

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Generated datasets for update per user system in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/update_per_user_system/rundll32_updateperusersystem.log

*Author: Teoderick Contreras, Splunk*

---

## T1218.012

**Description:** manual verclsid commandline data sets.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1218.013

**Description:** Atomic Test T1218 simulated for MavInject.exe

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haah*

---

## T1219

**Description:** Atomic Red Team tests simulating remote access software installation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Basic usage of teamviewer.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Basic installation and usage of screenconnect RMM application for testing needs.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

---

## T1220

**Description:** Atomic Red Team tests simulating XSL execution with msxsl and wmic.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1222.001

**Description:** Generated datasets for fsutil SymlinkEvaluation set in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

**Description:** This dataset contains process execution logs of subinacl.exe from Windows Sysmon logs.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

**Description:** Generated datasets for attrib hidden in attack range.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/attrib_hidden/security.log

*Author: Teoderick Contreras*

---

## T1222.002

**Description:** Generated datasets for linux auditd chmod exec attrib in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd chattr i in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1482

**Description:** Simulated execution of T1482 from Atomic Red Team and manually.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Simulated execution of T1482 from Atomic Red Team, mimicking Ryuk Ransomware actor tradecraft.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1484

**Description:** Modification of Active Directory and Windows domain policies and elements.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484/logAllPowerSploitModulesWithOldNames.log

*Author: Stanislav Miskovic*

**Description:** Executing the Set-DCShadowPermissions.ps1 powershell script to apply the minimal permissions required to perform a DCShadow attack.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

**Description:** Manually applying the necessary privileges to perform the DCSync attack via adsiedit.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

---

## T1484.001

**Description:** Manually disabling an active directory GPO using the Group Policy Management Console.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

**Description:** Manual Group Policy Object modification on a domain controller.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

**Description:** Manually adding a new client side extension to an existing an active directory group policy using the Group Policy Management Console.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

---

## T1484.002

**Description:** Manually added a new trusted domain using the Azure Portal and updated federation settings using AADInternals. Tenant specific details like tenant id, user names, etc. have been modified.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1485

**Description:** Manual generation of attack data by creating a file with a known ransomware filename GetYouFiles.txt

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Generated datasets for linux auditd no preserve root in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** sdelte execution data sets.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1486

**Description:** Manual generation of dcrypt utility.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Manual generation of attack data by creating a file with a known ransomware filename test.txt in Windows32 folder

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** A sample event with a known abusedd manage-bde command.

**Sourcetypes:** `XmlWinEventLog`

### Data Sources
- XmlWinEventLog

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/bitlocker_sus_commands/bitlocker_sus_commands.log

*Author: Steven Dick*

---

## T1489

**Description:** Generated datasets for linux auditd auditd service stop in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for splunk in attack range.

**Sourcetypes:** `splunkd_access`

### Data Sources
- splunkd_access

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: splunkd_access
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1489/splunk_kvstore_csrf/splunk_kvstore_csrf.log

*Author: Rod Soto, Splunk*

**Description:** Generated datasets for linux auditd sysmon service stop.log in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1490

**Description:** Dataset which contains an event for suspension of AWS bucket versioning.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

**Description:** Automatically categorized datasets in directory known_services_killed_by_ransomware

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Atomic Test Results: Successful Execution of test T1490-1 Windows - Delete Volume Shadow Copies Successful Execution of test T1490-2 Windows - Delete Volume Shadow Copies via WMI Return value unclear for test T1490-3 Windows - Delete Windows Backup Catalog Successful Execution of test T1490-4 Windows - Disable Windows Recovery Console Repair Return value unclear for test T1490-5 Windows - Delete Volume Shadow Copies via WMI with PowerShell Successful Execution of test T1490-6 Windows - Delete Backup Files

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1496

**Description:** Generated datasets for process high cpu usage in attack range.

**Sourcetypes:** `ps_metric`

### Data Sources
- ps_metric

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: ps_metric
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1496/process_high_cpu_usage/linux_max_cpu2.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for process high mem usage in attack range.

**Sourcetypes:** `ps_metric`

### Data Sources
- ps_metric

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: ps_metric
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1496/process_high_mem_usage/linux_max_mem.log

*Author: Teoderick Contreras, Splunk*

---

## T1497

**Description:** Generated datasets for chrom no sandbox in attack range.

**Sourcetypes:** `XmlWinEventLog:Security`

### Data Sources
- XmlWinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497/chrom_no_sandbox/chrome-no_sandbox.log

*Author: Teoderick Contreras, Splunk*

---

## T1497.003

**Description:** Generated datasets for ping sleep in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for time delay using choice exe in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497.003/time_delay_using_choice_exe/snakekeylogger_choice.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for njrat ping delay before delete in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497.003/njrat_ping_delay_before_delete/ping_0.log

*Author: Teoderick Contreras, Splunk *

---

## T1498

**Description:** CVE-2021-3422 Attempted Exploitation

**Sourcetypes:** `splunkd`

### Data Sources
- splunkd

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: splunkd
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1498/splunk_indexer_dos/splunkd.log

*Author: Lou Stella*

---

## T1499

**Description:** CVE-2022-37439 Attempted Exploitation

**Sourcetypes:** `splunkd`

### Data Sources
- splunkd

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: splunkd
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1499/splunk/splunk_zip_bomb_vulnerability.log

*Author: Jose Hernandez*

**Description:** None

**Sourcetypes:** `investigation_rest_handler`

### Data Sources
- investigation_rest_handler

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: investigation_rest_handler
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1499/splunk/splunk_cve_2024_22164_investigation_rest_handler.log

*Author: Rod Soto*

---

## T1505.001

**Description:** Common SQL Server abuse simulation data

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1505.003

**Description:** The following data was produced to emulate IIS, w3wp.exe, spawning shells, simulating web shell activity. In addition, behavior related to Microsoft Exchange Server's Unified Messaging services, umworkerprocess.exe and umservice.exe, spawning a child process. Behaviors are related to vulnerabilities exploited by HAFNIUM Group. The vulnerabilities recently being exploited were CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, and CVE-2021-27065.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Manual generation of attack data for generic webshell exploitation activity. Simulates a few webshell type behaviors as system user.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/generic_webshell_exploit/generic_webshell_exploit.log

*Author: Steven Dick*

**Description:** Generation of attack data related to CVE-2025-53770 (ToolShell) showing file creation of the malicious spinstall0.aspx web shell in SharePoint layouts directories.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1505.004

**Description:** The following data was produced to emulate suspicious IIS Module activity on Windows.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1505.006

**Description:** Sample of ESXi syslog events showing attempted forced installation of malicious VIBs

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## T1525

**Description:** Use the searches in this story to monitor your Kubernetes registry repositories for upload, and deployment of potentially vulnerable, backdoor, or implanted containers. These searches provide information on source users, destination path, container names and repository names. The searches provide context to address Mitre T1525 which refers to container implantation upload to a company's repository either in Amazon Elastic Container Registry, Google Container Registry and Azure Container Registry.

**Sourcetypes:** `aws:cloudtrail`

### Data Sources
- aws:cloudtrail

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudtrail
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1525/container_implant/container_implant_1.json

*Author: Rod Soto*

---

## T1526

**Description:** Dataset which contains cloudtrail logs from cloudsploit.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Dataset which contains kube-hunter scanning

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Kubernetes audit logs which contains pulling a image.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1528

**Description:** Used 365-stealer and a multi-tenant application registration to simulate a consent grant attack and declined the consent when presented

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Used 365-stealer and a multi-tenant application registration to simulate a consent grant attack.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Leveraged TokenTactics to perform device code phishing against an azure ad account

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1529

**Description:** Sample of ESXi syslog events showing commands used for bulk termination of VMs.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

**Description:** Sample of Linux auditd events showing potential abuse of the Magic SysRq key to manipulate or destabilize the system.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Milad Cheraghi*

---

## T1530

**Description:** Dataset which contains cloudtrail logs and the creation of a public S3 bucket.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Dataset which contains an AWS exfiltration attempt from S3 buckets, high number of file downloads using GetObject

**Sourcetypes:** `aws:cloudtrail`

### Data Sources
- aws:cloudtrail

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudtrail
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json

*Author: Bhavin Patel*

---

## T1531

**Description:** Generated datasets for log off user in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1531/log_off_user/pwh_quser_logoff.log

*Author: Teoderick Contreras, Splunk*

**Description:** Atomic Red Team tests simulating delete net user.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for linux unix delete user in attack range.

**Sourcetypes:** `syslog`

### Data Sources
- syslog

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: syslog
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1531/linux_unix_delete_user/linux_del_user.log

*Author: Teoderick Contreras, Splunk*

---

## T1537

**Description:** Automatically categorized datasets in directory high_frequency_copy_of_files_in_network_share

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** simulated data sets of high frequency copy of files or documents in network share

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/high_copy_files_in_net_share/security.log

*Author: Teoderick Contreras*

**Description:** Adversaries made suspicious AWS AMI attribute modifications, such as sharing it with another AWS account or making the full AMI image public. Adversaries are known to abuse these APIs to exfiltrate sensitive organization information stored in the AWS Resources, there by its very important to monitor these seemingly benign API activity in Cloudtrail logs.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

---

## T1539

**Description:** Manually generated dataset of two sessions from mutiple IPs, useragents, etc

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

---

## T1542.003

**Description:** Attack data for bootkits

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Automated Attack Data Service*

---

## T1543.003

**Description:** Simulated attack using KrbRelayUp

**Sourcetypes:** `WinEventLog:System`

### Data Sources
- WinEventLog:System

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:System
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/krbrelayup/windows-system.log

*Author: Michael Haag, Splunk*

**Description:** Atomic Test Results: Return value unclear for test T1543.003-1 Modify Fax service to run PowerShell Return value unclear for test T1543.003-2 Service Installation CMD Return value unclear for test T1543.003-3 Service Installation PowerShell

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Automated Attack Data Service*

**Description:** Manually using the sc.exe binary to create and start a Windows Service on a remote endpoint for lateral movement and remote code execution.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1546

**Description:** Used powershell to modify the ACL of the AdminSDHolder active directory object.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Sample events for CompatTelRunner abuse.

**Sourcetypes:** `XmlWinEventLog`

### Data Sources
- XmlWinEventLog

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546/compattelrunner_abuse/compattelrunner_abuse.log

*Author: Steven Dick*

---

## T1546.001

**Description:** Manual generation of attack data for txtfile default file association registry entry for persistence and privilege escalation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1546.002

**Description:** Manual generation of attack data for SCRNSAVE.EXE registry entry for persistence and privilege escalation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1546.003

**Description:** Atomic Test Results: Return value unclear for test T1546.003-1 Persistence via WMI Event Subscription

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Manual WMI persistence via WMI Event Subscription

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Automated Attack Data Service*

---

## T1546.004

**Description:** Generated datasets for linux init profile in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for linux auditd unix shell mod config in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1546.008

**Description:** Generation of Atomic Red Team technique T1546.008

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1546.011

**Description:** Atomic Test Results: Successful Execution of test T1546.011-1 Application Shim Installation Return value unclear for test T1546.011-2 New shim database files created in the default shim database directory Successful Execution of test T1546.011-3 Registry key creation and/or modification events for SDB

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1546.012

**Description:** Atomic Test Results: Successful Execution of test T1546.012-1 IFEO Add Debugger Successful Execution of test T1546.012-2 IFEO Global Flags

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1546.015

**Description:** simulate colorui uac bypass technique.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for pwh com object in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Atomic Test Results: Successful Execution of test T1546.015 related to inprocserver32

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1547.001

**Description:** Atomic Test Results: Successful Execution of test T1547.001-1 Reg Key Run Successful Execution of test T1547.001-2 Reg Key RunOnce Return value unclear for test T1547.001-3 PowerShell Registry RunOnce Successful Execution of test T1547.001-4 Suspicious vbs file run from startup Folder Successful Execution of test T1547.001-5 Suspicious jse file run from startup Folder Return value unclear for test T1547.001-6 Suspicious bat file run from startup Folder

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1547.003

**Description:** manual timeprovider registry modification datasets for persistence and privilege escalation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1547.005

**Description:** Manually copying mimilib.dll over to system32 & registering the dll as a new SSP via registry. Attack was ran successfully against a non-domain joined windows device, and a domain joined windows sever. (Also applicable against DCs)

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Dean Luxton*

---

## T1547.006

**Description:** Generated datasets for linux auditd rmmod in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd modprobe unload module in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd modprobe new in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1547.008

**Description:** Generation of Atomic Red Team technique T1547.008

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1547.010

**Description:** Generation of Atomic Red Team technique T1547.010

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1547.011

**Description:** Generation of Atomic Red Team technique T1547.011 with plutil and osquery

**Sourcetypes:** `osquery:results`

### Data Sources
- osquery:results

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: osquery:results
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.011/atomic_red_team/osquery.log

*Author: Patrick Bareiss*

---

## T1547.012

**Description:** manual printer processor registry modification datasets for persistence and privilege escalation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Automated generation of attack data by exploiting CVE-2021-1675

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Teoderick Contreras, Mauricio Velazco*

---

## T1548

**Description:** Privilege elevation abuse.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/logAllPowerSploitModulesWithOldNames.log

*Author: Stanislav Miskovic*

**Description:** GDB linux living off the land and privilege escalation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Gowthamaraj Rajendran, Splunk*

**Description:** Docker linux living off the land and privilege escalation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Gowthamaraj Rajendran, Splunk*

---

## T1548.001

**Description:** Generated datasets for linux setcap in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for linux auditd setuid in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for chmod uid in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1548.002

**Description:** Generation of slui.exe UAC Bypass behaviors.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

**Description:** Generation of Atomic Red Team technique T1548.002

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Detection of common User Account Control bypass techniques, generated using Atomic Tests for T1548.002

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

---

## T1548.003

**Description:** Generated datasets for linux auditd doas new in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for sudoers temp in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for linux auditd sudo su in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1550

**Description:** Over pass the hash attack using impackets getTGT script.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550/impacket/windows-security.log

*Author: Mauricio Velazco*

**Description:** Automatically categorized datasets in directory kerberos_tgt_request_using_rc4_encryption

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Over pass the hash attack using Rubeus.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1550.002

**Description:** Anonymized datasets on Pass the Hash and Pass the Token exploits extracted from real datasets.

**Sourcetypes:** `WinEventLog:Security, WinEventLog:Security`

### Data Sources
- WinEventLog:Security
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security, WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.002/ptt_pth_kerb_ntlm_anon_DC_dataset.log

*Author: Stanislav Miskovic*

**Description:** Manual generation of attack data including pass the hash attack with mimikatz and psexec.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1550.003

**Description:** Pass the ticket attack using mimikatz.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Pass the ticket attack using rubeus.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1552

**Description:** Generated datasets for snakey keylogger outlook reg access in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552/snakey_keylogger_outlook_reg_access/snakekeylogger_4663.log

*Author: Teoderick Contreras, Splunk*

**Description:** Automatically categorized datasets in directory aws_getpassworddata

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Generated datasets for windows post exploitation in attack range.

**Sourcetypes:** `stash`

### Data Sources
- stash

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: stash
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552/windows_post_exploitation/windows_post_exploitation_risk.log

*Author: Teoderick Contreras, Splunk*

---

## T1552.001

**Description:** Linux SSH authentication logs containing a password where the username is expected.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mikael Bjerkeland*

**Description:** Generated datasets for file xml config in attack range.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.001/file_xml_config/filezilla_obj.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for ie intelliform storage in attack range.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.001/ie_intelliform_storage/storage2_sim.log

*Author: Teoderick Contreras, Splunk*

---

## T1552.002

**Description:** Simulated datasets for creation of autoadminlogon entry in registry name.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1552.004

**Description:** Generated datasets for linux auditd find ssh files in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd find gpg in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** This search looks for arguments to certutil.exe indicating the manipulation or extraction of Certificate. This certificate can then be used to sign new authentication tokens specially inside Federated environments such as Windows ADFS.

**Sourcetypes:** `aws:cloudtrail`

### Data Sources
- aws:cloudtrail

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudtrail
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T552.004/certutil_exe_certificate_extraction/certutil_exe_certificate_extraction.raw

*Author: Rod Soto*

---

## T1552.006

**Description:** Manually executed PowerSploit's commandlets to retrieve GPP credentials Get-GPPPassword and Get-CachedGPPPassword

**Sourcetypes:** `WinEventLog:Microsoft-Windows-PowerShell/Operational`

### Data Sources
- WinEventLog:Microsoft-Windows-PowerShell/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Microsoft-Windows-PowerShell/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.006/powershell_gpp_discovery/win-powershell.log

*Author: Mauricio Velazco*

**Description:** Manually executed findstr attempt to find retrieve GPP credentials.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1552.007

**Description:** Kubernetes audit log to retrieve a secret from k8s.

**Sourcetypes:** `aws:cloudwatchlogs`

### Data Sources
- aws:cloudwatchlogs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudwatchlogs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.007/kube_audit_get_secret/kube_audit_get_secret.json

*Author: Patrick Bareiss*

---

## T1553.003

**Description:** Manual testing of adding a SIP provider to the registry

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1553.004

**Description:** Atomic Test Results: Return value unclear for test T1553.004-4 Install root CA on Windows Successful Execution of test T1553.004-5 Install root CA on Windows with certutil

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1553.005

**Description:** Detection of unsigned MSIX package installation using PowerShell

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Generated datasets for mark of the web bypass in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1553.005/mark_of_the_web_bypass/possible-motw-deletion.log

*Author: Teoderick Contreras, Splunk*

---

## T1554

**Description:** Manual generation of attack data by disabling a security step in Circle CI.

**Sourcetypes:** `circleci`

### Data Sources
- circleci

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: circleci
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1554/circle_ci_disable_security_step/circle_ci_disable_security_step.json

*Author: Patrick Bareiss*

**Description:** Manual generation of attack data by disabling a security job in Circle CI.

**Sourcetypes:** `circleci`

### Data Sources
- circleci

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: circleci
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1554/circle_ci_disable_security_job/circle_ci_disable_security_job.json

*Author: Patrick Bareiss*

---

## T1555

**Description:** Generated datasets for cmdkey create credential store in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/cmdkey_create_credential_store/cmdkey_gen_sys.log

*Author: Teoderick Contreras, Splunk*

**Description:** simulated brwser pass view application used by remcos in attackrange

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Datasets containing in-line calls to all critical Mimikatz and PowerSploit modules

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/applying_stolen_credentials/logAllMimikatzModules.log

*Author: Stanislav Miskovic*

---

## T1555.003

**Description:** Generated datasets for browser credential info temp in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555.003/browser_credential_info_temp/braodo_browser_info.log

*Author: Teoderick Contreras, Splunk*

---

## T1555.004

**Description:** Generated datasets for vaultcli creds in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555.004/vaultcli_creds/vaultcli.log

*Author: Teoderick Contreras, Splunk*

---

## T1555.005

**Description:** Generated datasets for linux auditd find credentials in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd find password db in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1556

**Description:** Created a policy which denies access in Duo.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Created a policy which allow old Flash and Java versions in Duo.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Disbale mfa for user in Office 365.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1556.001

**Description:** Atomic testing with T1553.005 related to lnk and iso.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1556.006

**Description:** Registed new MFA methods for an Azure AD account

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Using the Okta admin portal, disabled MFA for a user.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Registed new MFA methods for an AWS Account

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

---

## T1557.002

**Description:** cisco ios logs

**Sourcetypes:** `cisco:ios`

### Data Sources
- cisco:ios

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: cisco:ios
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1557.002/cisco_ios/cisco_ios.log

*Author: Patrick Bareiss*

---

## T1558

**Description:** Automatically categorized datasets in directory windows_computer_account_requesting_kerberos_ticket

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Manual simulation of the diamond ticket attack using rubeus and mimikatz.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manual simulation of krbrelayup.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log

*Author: Michael Haag*

---

## T1558.001

**Description:** Manual golden ticket attack with Impacket using ticketer.py to create the golden ticket and wmiexec.py to leverage the ticket and obtain a code execution on a domain controller.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.001/impacket/windows-security.log

*Author: Mauricio Velazco*

**Description:** Automatically categorized datasets in directory kerberos_service_ticket_request_using_rc4_encryption

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

---

## T1558.002

**Description:** Manual silver ticket attack with Impacket using ticketer.py to create the silver ticket and wmiexec.py to leverage the ticket and obtain a code execution on host.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.002/impacket/windows-security.log

*Author: Mauricio Velazco*

---

## T1558.003

**Description:** Automatically categorized datasets in directory kerberoasting_spn_request_with_rc4_encryption

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Manual kerberoasting attack with mimikatz. Changed the kerberos encryption type to RC4.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Using PowerView manually to get SPN accounts using Get-DomainUser or Get-NetUser

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Gowthamaraj rajendran*

---

## T1558.004

**Description:** Using PowerShell to manually update the Kerberos Pre Authentication flag on a domain account using Set-ADAccountControl.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually enumerating domain accounts with Kerberos Pre-Authentication disabled using Get-ADUser.

**Sourcetypes:** `WinEventLog:Microsoft-Windows-PowerShell/Operational, XmlWinEventLog:Microsoft-Windows-PowerShell/Operational, WinEventLog:Security`

### Data Sources
- WinEventLog:Microsoft-Windows-PowerShell/Operational
- XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Microsoft-Windows-PowerShell/Operational, XmlWinEventLog:Microsoft-Windows-PowerShell/Operational, WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.004/getaduser/windows-powershell.log

*Author: Mauricio Velazco*

**Description:** Manually enumerating domain accounts with Kerberos Pre-Authentication disabled using PowerView.

**Sourcetypes:** `WinEventLog:Microsoft-Windows-PowerShell/Operational, WinEventLog:Security`

### Data Sources
- WinEventLog:Microsoft-Windows-PowerShell/Operational
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Microsoft-Windows-PowerShell/Operational, WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.004/powerview/windows-powershell.log

*Author: Mauricio Velazco*

---

## T1559

**Description:** Generated datasets for anonymous pipe in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1559/anonymous_pipe/anonymouspipe.log

*Author: Teoderick Contreras, Splunk*

---

## T1560

**Description:** Generated datasets for archived in temp dir in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560/archived_in_temp_dir/braodo_zip_temp.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for powershell archive in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-PowerShell/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560/powershell_archive/powershell_archive.log

*Author: Teoderick Contreras, Splunk*

---

## T1560.001

**Description:** The following data was using archive tools from the command line

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_tools/windows-security.log

*Author: Patrick Bareiss*

**Description:** The following data was generated with Cobalt Strike spawning 7z.exe to archive files on disk.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Generated datasets for archive utility darkgate in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560.001/archive_utility_darkgate/rar_sys.log

*Author: Teoderick Contreras, Splunk*

---

## T1561.002

**Description:** Generated datasets for mbr raw access in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

---

## T1562

**Description:** Sample of ESXi syslog events showing modification to ESXi VIB acceptance levels.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

**Description:** The following is data related to Windows AppLocker Testing.

**Sourcetypes:** `xmlwineventlog`

### Data Sources
- xmlwineventlog

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: xmlwineventlog
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/applocker/applocker.log

*Author: Michael Haag*

**Description:** Sample of ESXi syslog events showing ESXi lockdown settings being modified to impair defenses.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## T1562.001

**Description:** Generated datasets for defender exclusion sysmon in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for disable defender logging in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for rmdir defender pwsh in attack range.

**Sourcetypes:** `WinEventLog:Microsoft-Windows-PowerShell/Operational`

### Data Sources
- WinEventLog:Microsoft-Windows-PowerShell/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Microsoft-Windows-PowerShell/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/rmdir_defender_pwsh/powershell.log

*Author: Teoderick Contreras*

---

## T1562.002

**Description:** This dataset contains registry set logs from Windows Sysmon logs related to modification of the ChannelAccess and CustomSD registry values.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

**Description:** This dataset contains Process Creation and policy change logs set logs from Windows Sysmon and Security, related to abuse of auditpol to change, remove and clear the audit policy.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

---

## T1562.003

**Description:** Sample of ESXi syslog events showing attempts to modify the loghost configuration.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

**Description:** Sample of ESXi syslog events showing tampering of audit settings.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

**Description:** Sample of ESXi syslog events showing attempts to modify the syslog configuration.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## T1562.004

**Description:** Generated datasets for njrat add firewall rule in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for firewall win event in attack range.

**Sourcetypes:** `XmlWinEventLog:Security`

### Data Sources
- XmlWinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/firewall_win_event/MPSSVC_Rule-Level_Policy_Change-4948.log.txt

*Author: Teoderick Contreras, Splunk*

**Description:** atomic red team execution of technique T1562.004

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1562.006

**Description:** This dataset contains registry set logs from Windows Sysmon logs related to setting the COMPlus_ETWEnabled value as an envinronment variable.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.006/dotnet_etw_bypass/dotnet_etw_bypass.log

*Author: Nasreddine Bencherchali, Splunk*

---

## T1562.007

**Description:** Dataset containing activity from O365 when IP addresses are added to Trusted IP list such that the attackers can bypass MFA

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

**Description:** Dataset which contains cloudtrail logs and the creation of a acl with all ports open.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

**Description:** Dataset which contains cloudtrail logs and the deletion of a acl rule.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1562.008

**Description:** Manually disabled advanced audit logging for one user in O365. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco, Splunk*

**Description:** Dataset which contains cloudtrail events when a cloudwatch log group is deleted.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Gowthamaraj Rajendran, Splunk*

**Description:** Dataset which contains cloudtrail events with a deletes of AWS Services like CloudWatch, Guardduy, Web Application Firewalls.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel, Splunk*

---

## T1562.012

**Description:** Generated datasets for auditd daemon end in attack range.

**Sourcetypes:** `auditd`

### Data Sources
- auditd

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: auditd
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.012/auditd_daemon_end/linux_daemon_end.log

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for auditd daemon type in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1563.002

**Description:** Atomic Testing of RDP Hijacking

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Automatically categorized datasets in directory windows_rdp_connection_successful

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

---

## T1564

**Description:** This dataset contains process execution logs from Windows Sysmon logs related to execution of sc.exe with the sdset flag.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

---

## T1564.001

**Description:** Generated datasets for linux auditd hidden file in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1564.003

**Description:** Simulated attacks using conhost with --headless

**Sourcetypes:** `XmlWinEventLog`

### Data Sources
- XmlWinEventLog

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1564.003/headless/4688_conhost_headless.log

*Author: Michael Haag*

---

## T1564.004

**Description:** Detection of common behaviors used to abouse NTFS alternate datastreams.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

---

## T1564.008

**Description:** Detection of suspicious mailbox rule creation.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: unknown*

---

## T1565.001

**Description:** Generated datasets covering the execution of wbadmin for recovery in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

---

## T1566

**Description:** Data generaeted for CVE-2024-21378

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Various Office 365 built-in and premium security feature alerts.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

**Description:** Synthentic Dataset generated for Zscaler detections for Blocked activities

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin patel, Gowtham*

---

## T1566.001

**Description:** Simulated attacks using Unicorn, Cobalt Strike, and Metasploit. These tests all include macros and a Office Product spawning a process.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon.log

*Author: Michael Haag*

**Description:** Simulated test Gsuite Datasets for email having suspicious link

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for office doc abuses rels in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1566.002

**Description:** Evilginx2 DNS activity captured by Stream. Custom attack_range config using DC to delegate DNS to evilginx2; web traffic proxied through the Splunk server which was running Stream and resolving DNS via DC.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Peter Gael*

**Description:** lnk file in temp folder

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1567

**Description:** Simulate usage of the gdrive binary to interact with Google Drive.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

**Description:** Simulate Large Web upload with high bytes out

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel, Splunk*

**Description:** Sample of events when an actor attempts to exfiltrate data from sharepoint using various methods.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

---

## T1567.002

**Description:** Simulated test Gsuite Datasets for sharing drive outside organizational email

**Sourcetypes:** `gsuite:drive:json`

### Data Sources
- gsuite:drive:json

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: gsuite:drive:json
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1567.002/gsuite_share_drive/gdrive_share_external.log

*Author: Teoderick Contreras*

---

## T1569

**Description:** Illegal service or process control.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569/logAllMimikatzModules.log

*Author: Stanislav Miskovic*

---

## T1569.002

**Description:** Generated datasets for linux service start in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** This dataset contains process execution logs from Windows Sysmon logs related to execution of sc.exe with the sdset flag.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

**Description:** Atomic Testing of Remcom

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1570

**Description:** Atomic Testing of Remcom

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1572

**Description:** ngrok.exe execution on windows.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Simulation of plink activity.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** DNS Beaconing using Cobalt Strike 4.2. Activity was generated using Attack Range and Kali Linux. DNS Beaconing was performed using TXT and A records using the domain - getbobspizza.com.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1574.001

**Description:** This behavior is related to the POC for iscsicpl.exe.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Generated datasets for firewall api path in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Atomic Test Results: Successful Execution of test T1574.001

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1574.002

**Description:** Generated datasets for unsigned dll load in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.002/unsigned_dll_load//wineloader_dll_sideload.log

*Author: Teoderick Contreras, Splunk*

**Description:** This behavior is related to the POC for InstallerFileTakeOver.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Generated datasets for unsigned dll loaded same process path in attack range.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.002/unsigned_dll_loaded_same_process_path/unsigned_dll_process_path.log

*Author: Teoderick Contreras, Splunk*

---

## T1574.006

**Description:** Generated datasets for lib hijack in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras*

**Description:** Generated datasets for linux auditd preload file in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

**Description:** Generated datasets for linux auditd ldpreload in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1574.009

**Description:** Atomic Test Results: Successful Execution of test T1574.009-1 Execution of program.exe as service with unquoted service path

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1574.011

**Description:** change serice ImagePath with reg.exe

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Patrick Bareiss*

---

## T1578.005

**Description:** Contains dataset for AWS security group changes

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

---

## T1580

**Description:** Dataset which contains cloudtrail logs showcasing different behavior detections related to AWS IAM.

**Sourcetypes:** `aws:cloudtrail`

### Data Sources
- aws:cloudtrail

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudtrail
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_iam_excessive_list_command_usage/aws_iam_excessive_list_command_usage.json

*Author: Michael Haag*

**Description:** Automatically categorized datasets in directory aws_iam_assume_role_policy_brute_force

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Automatically categorized datasets in directory aws_iam_accessdenied_discovery_events

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

---

## T1584

**Description:** Sample of ESXi syslog events showing dormant VMs being activated.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## T1585

**Description:** Illegal account creation via PowerSploit modules.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1585/illegal_account_creation/logAllPowerSploitModulesWithOldNames.log

*Author: Stanislav Miskovic*

---

## T1586.003

**Description:** This dataset is synthetically generated using by simulating events in a lab

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

**Description:** This dataset is synthetically generated using by simulating console login attempts from aws console

**Sourcetypes:** `aws:cloudtrail`

### Data Sources
- aws:cloudtrail

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: aws:cloudtrail
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1586.003/aws_console_login_multiple_ips/cloudtrail.json

*Author: Bhavin Patel*

---

## T1587.002

**Description:** This behavior is related to a root certificate being added to the CurrentUser store.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

---

## T1587.003

**Description:** Manual generation of attack data using Splunk

**Sourcetypes:** `splunkd`

### Data Sources
- splunkd

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: splunkd
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T587.003/splunk_fwder/splunkd.log

*Author: Lou Stella*

**Description:** Generated datasets for add store cert in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1588.002

**Description:** This behavior is related to the advancedrun.exe.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Generated datasets covering the creation or execution of NirSof ttooling.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Nasreddine Bencherchali, Splunk*

---

## T1589.002

**Description:** Automatically categorized datasets in directory kerberos_user_enumeration

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

**Description:** Kerberos user enumeration using kerbrute.

**Sourcetypes:** `WinEventLog:Security`

### Data Sources
- WinEventLog:Security

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: WinEventLog:Security
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1589.002/kerbrute/windows-security.log

*Author: Mauricio Velazco*

---

## T1590.002

**Description:** Generated datasets for enum dns record in attack range.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Teoderick Contreras, Splunk*

---

## T1590.005

**Description:** Automatically categorized datasets in directory T1590.005

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Generated by dataset_analyzer.py*

---

## T1595

**Description:** This dataset contains execution of commonly used attacker tool found in HoneyPot for XMRig, specifically- MassScan_GUI.exe and masscan.exe

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel*

**Description:** A set of events related generic powershell/sysmon network enumeration.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

---

## T1598.002

**Description:** This dataset contains RDP file execution events from Windows Sysmon logs.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag, Splunk*

---

## T1601.001

**Description:** Sample of ESXi syslog events showing failed attempts to install malicious VIBs.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## T1611

**Description:** Generated datasets for Cisco Isovalent Process Exec EventType. Contains simulations for the escaping from host.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel, Splunk*

---

## T1620

**Description:** Manually using Nimplant to execute Rubeus using the execute-assembly function.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1621

**Description:** Detection of a few common MFA abuse scenarios with datasets from pindID

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

**Description:** Manually authenticated to the Azure AD Portal failed to pass MFA challenge by denying it or letting it timeout. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

**Description:** Manually generated multple MFA requests for a user leveraing the Azure AD Portal. Tenant specific details have been replaced in the dataset including tenant id, user names, ips, etc.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Mauricio Velazco*

---

## T1647

**Description:** Generation of Atomic Red Team technique T1547.011 with plutil and osquery

**Sourcetypes:** `osquery:results`

### Data Sources
- osquery:results

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: osquery:results
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.011/atomic_red_team/osquery.log

*Author: Patrick Bareiss*

---

## T1649

**Description:** Generation of Atomic Red Team techniques that create and export a certificate on Windows, simulating an adversary stealing certificates.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Michael Haag*

**Description:** Detection of common behaviors when certify/certipy tools are used to exploit  AD CS for the ESC1 vulnerablity. Manual testing using standard compiled versions of both tools

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Steven Dick*

---

## T1654

**Description:** This dataset contains multiple events that simulate event log enumeration on a windows machine, using built-in utilities.

**Sourcetypes:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Data Sources
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

**Sample Data:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/eventlog_enumeration/eventlog_enumeration.yml

*Author: Nasreddine Bencherchali*

---

## T1673

**Description:** Sample of ESXi syslog events VM discovery commands.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Raven Tait, Splunk*

---

## Unknown

**Description:** Logs from M365 Copilot Access Logs via Splunk Add-on for M365 and Exported Logs from eDsicovery Purview. Contains actual access logs and jailbreak attacks.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Rod Soto, Splunk*

**Description:** Generated datasets for Cisco Isovalent Process Exec EventType by manual /atomic-red team simulations in a K8s cluster running Tetragon

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Bhavin Patel, Splunk*

**Description:** Logs from Ollama server, contain errors, system messages, http calls, methods and endpoint uris.

**Sourcetypes:** `Various security logs`

### Data Sources
- Security event logs
- System logs
- Network logs

### Detection Strategy
1. **Log Collection**: Ensure you're collecting logs from: Various security logs
2. **Indicators to Monitor**:
   - Look for unusual patterns in the logs
   - Correlate events across multiple data sources
   - Monitor for technique-specific behaviors

*Author: Rod Soto, Splunk*

---

<!-- CHUNK: Part 2 - AlienVault OTX Threat Intelligence -->
# Part 2: AlienVault OTX Threat Intelligence

Real-world threat intelligence from AlienVault Open Threat Exchange (OTX).

<!-- CHUNK: Forbes Waterhole Attack -->
## Forbes.com Waterhole Attack

**Adversary:** Codoso

**Summary:** A Chinese advanced persistent threat (APT) compromised Forbes.com to set up a watering hole style web-based drive-by attack against US Defense and Financial Services firms in late November 2014. The brazen attack used chained 0-days against Adobe Flash and Microsoft Internet Explorer 9  to attempt to gain access to internal networks at these companies. This report is the first to detail the attack against strategic US interests to China....

---

## Careto - The Masked APT

**Summary:** The Mask is an advanced threat actor that has been involved in cyber-espionage operations since at least 2007. The name "Mask" comes from the Spanish slang word "Careto" ("Ugly Face" or “Mask”) which the authors included in some of the malware modules....

---

## Hellsing APT

**Adversary:** Hellsing

**Summary:** The Hellsing APT group is currently active in the APAC region, hitting targets mainly in the South China Sea area, with a focus on Malaysia, the Philippines and Indonesia. The group has a relatively small footprint compared to massive operations such as "Equation". Smaller groups can have the advantage of being able to stay under the radar for longer periods of time, which is what happened here....

---

## Operation RussianDoll

**Adversary:** Sofacy

**Summary:** FireEye Labs recently detected a limited APT campaign exploiting zero-day vulnerabilities in Adobe Flash and a brand-new one in Microsoft Windows. Using the Dynamic Threat Intelligence Cloud (DTI), FireEye researchers detected a pattern of attacks beginning on April 13th, 2015. Adobe independently patched the vulnerability (CVE-2015-3043) in APSB15-06. Through correlation of technical indicators and command and control infrastructure, FireEye assess that APT28 is probably responsible for this ac...

---

## The CozyDuke APT

**Adversary:** APT 29

**Summary:** CozyDuke (aka CozyBear, CozyCar or "Office Monkeys") is a threat actor that became increasingly active in the 2nd half of 2014 and hit a variety of targets. The White House and Department of State are two of the most spectacular known victims....

---

## APT28 DOMAINS (REPORT)

**Adversary:** Sofacy

---

## APT30

**Adversary:** APT 30

**Summary:** Cyber Threat Group that Exploited Governments and Commercial Entities across Southeast Asia and India for over a Decade...

---

## From Quartermaster to Sunshop

**Summary:** The report details how many seemingly unrelated cyber attacks may, in fact, be part of a broader offensive fueled by a shared development and logistics infrastructure — a finding that suggests some targets are facing a more organized menace than they realize. Our research points to centralized planning and development by one or more advanced persistent threat (APT) actors. Malware clearly remains a desired cyber weapon of choice. Streamlining development makes financial sense for attackers, so t...

---

## The Curious Case of CZ Solution

**Summary:** While investigating an uptick in Spy-Net spam campaigns, we came across a malware binary that was digitally signed that struck our interest. Spy-Net allows an attacker to interact with the victim via a remote shell to upload/download files, interact with the registry, running processes and services as well as capture images of the desktop and record form the webcam and audio. It also contains functionality to extract saved passwords and turn the victim into a proxy server. During the build proce...

---

## XSLCmd OSX Backdoor

**Adversary:** APT41

**Summary:** FireEye Labs recently discovered a previously unknown variant of the APT backdoor XSLCmd – OSX.XSLCmd – which is designed to compromise Apple OS X systems. This backdoor shares a significant portion of its code with the Windows-based version of the XSLCmd backdoor that has been around since at least 2009....

---

## The Naikon APT

**Adversary:** Naikon

**Summary:** The Naikon APT aligns with the actor our colleagues at FireEye recently revealed to be APT30, but we haven’t discovered any exact matches. It is hardly surprising that there is an element of overlap, considering both actors have for years mined victims in the South China Sea area, apparently in search of geo-political intelligence....

---

## Hiding in Plain Sight: Chinese APT Group's Obfuscation Tactic

**Adversary:** Axiom

**Summary:** This IOC contains indicators detailed in the whitepaper "Hiding in Plain Sight: FireEye and Microsoft Expose Chinese APT Group's Obfuscation Tactic". This IOC contains indicators for the BLACKCOFFEE malware family that is attributed to APT17....

---

## The Naikon APT and the MsnMM Campaigns

**Adversary:** Naikon

**Summary:** For over half a decade, the Naikon APT waged multiple attack campaigns on sensitive targets throughout South-eastern Asia and around the South China Sea. It maintained a heavy offensive focus on Myanmar, Vietnam, Singapore, the Philippines, Malaysia, and Laos. Targets and victims included ASEAN governmental agencies and government departments, investment enterprises, military, law enforcement and border control organizations, embassies, university faculties and others....

---

## OPM Breach Analysis

**Summary:** Back in February, the ThreatConnect team conducted an  in-depth independent analysis of the Anthem breach, finding connections to amorphous Chinese APT activity. Although our primary concern at the time was with the malicious Wellpoint/Anthem and VAE, Inc. (a Federal contractor) command and control domains, we couldn’t help but notice a peculiar related OPM-themed domain, opm-learning[.]org. This finding was listed in our Anthem blog, and we have continued to monitor it in ThreatConnect since mi...

---

## Threat Spotlight: TeslaCrypt

**Summary:** One of the latest ransomware variants is called TeslaCrypt and appears to be a derivative of the original Cryptolocker ransomware. Although it claims to be using asymmetric RSA-2048 to encrypt files, it is making use of symmetric AES instead....

---

## Nuclear EK DELIVERS RANSOMWARE

---

## &#39;Los Pollos Hermanos&#39; crypto ransomware using PowerShell Empire

**Summary:** Crypto ransomware affecting Australian computers uses Breaking Bad theme in ransom demand....

---

## TeslaCrypt Ransomware

**Summary:** In early February 2015, Dell SecureWorks Counter Threat Unit(TM) (CTU) researchers investigated a new file-encrypting ransomware family named TeslaCrypt, which was distributed by the popular Angler browser exploit kit. After encrypting popular file types with the AES-256 encryption algorithm, TeslaCrypt holds the files for a ransom of $250 to $1000. The malware uses the Tor anonymity network for command and control (C2) and does not require network connectivity to encrypt files, which complicate...

---

## Angler EK delivers Alpha Crypt Ransomware

**Summary:** Angler EK analysis from http://malware-traffic-analysis.net/2015/04/30/index.html...

---

## Chinese Teens Take On the Mobile Ransomware Trade

**Summary:** A new breed of cybercriminals has surfaced in China. They are bolder and more reckless than their more experienced veteran counterparts. All born in the 90s, these neophytes are not afraid to get caught, carelessly leaving a trail of traceable contact details online. They find and share readily available code and use those to make their own malware. It’s these same teens that are causing a surge in mobile ransomware in the Chinese underground market....

---

## Angler EK: More Obfuscation, Fake Extensions, and Other Nonsense

**Summary:** Late last week Talos researchers noticed a drastic uptick in Angler Exploit Kit activity. We have covered Angler previously, such as the discussion of domain shadowing. This exploit kit evolves on an almost constant basis. However, the recent activity caught our attention due to  a change to the URL structure of the landing pages. This type of change doesn’t occur often and was coupled with some other interesting tidbits including how the HTTP 302 cushioning has evolved and the payload of anothe...

---

## Cryptowall Spam: My Resume Protects All Your Files

**Summary:** Talos has found a new SPAM campaign that is using multiple layers of obfuscation to attempt to evade detection.  Spammers are always evolving to get their messages to the end users by bypassing SPAM filters while still appearing convincing enough to get a user to complete the actions required to infect the system. The end payload for this campaign is Cryptowall 3.0. Talos has covered this threat repeatedly and this is another example of how the success of Ransomware has pushed it to one of the t...

---

## Magnitude Exploit Kit Uses Newly Patched Adobe Vulnerability

**Summary:** Adobe may have already patched a Flash Player vulnerability last week, but several users—especially those in the US, Canada, and the UK —are still currently exposed and are at risk of getting infected with CryptoWall 3.0. The Magnitude Exploit Kit included an exploit, detected as SWF_EXPLOIT.MJTE, for the said vulnerability, allowing attackers to spread crypto-ransomware into their target systems....

---

## Locker: an Android ransomware full of surprises

**Summary:** Android ransomware that claims it has detected "forbidden pornographic" pictures on your device, says it has reported it to the FBI and asks you to pay a fine of $500. To make the (fake) report appear even more scary, the malware displays your IP address and a picture of you. It says those were sent in the report to the FBI....

---

## Analysis of a piece of ransomware in development (CryptoApp)

**Summary:** Ransomware sure has had an uptick the past years; more and more variants appear while some have been leading the pack for the past years. This article is on a new ‘strain’, it dates to March this year from what I can tell. I haven’t seen any write-up or info about it yet (nor had any major incidents at $dayjob or heard of it from any other analysts). From what I can tell its still under development, this article will tell the story of this ransomware.
From http://blog.0x3a.com/post/126900680679/...

---

## CryptoApp ransomware:  changes & active campaign

**Summary:** Ransomware sure has had an uptick the past years; more and more variants appear while some have been leading the pack for the past years. This article is on a new ‘strain’, it dates to March this year from what I can tell. I haven’t seen any write-up or info about it yet (nor had any major incidents at $dayjob or heard of it from any other analysts). From what I can tell its still under development, this article will tell the story of this ransomware.
Not even a day ago I blogged on a piece of r...

---

## The Shade Encryptor: a Double Threat

**Summary:** A family of ransomware Trojans that encrypts files and adds the extensions “.xtbl” and “.ytbl” emerged in late 2014/early 2015, and quickly established itself among the top three most widespread encryptors in Russia (along with Trojan-Ransom.Win32.Cryakl and Trojan-Ransom.BAT.Scatter). This threat has been assigned the verdict Trojan-Ransom.Win32.Shade according to Kaspersky Lab’s classification. The original name given to the encryptor by its creator is not known; other security vendors detect ...

---

## DragonOK Backdoor Malware Deployed Against Japanese Targets

**Summary:** This campaign involved five separate phishing attacks, each carrying a different variant of Sysget malware, also known as HelloBridge. The malware was included as an attachment intended to trick the user into opening the malware. This included altering the icon of the executable to appear as other file types as well as decoy documents to trick users into thinking they had opened a legitimate file....

---

## Targeted Crimeware in the Midst of Indiscriminate Activity

**Summary:** Although we have observed low volume spam campaigns by some cybercriminals who have purchased MWI, we recently discovered spearphishing emails by one group using MWI to direct an attack against point-of-sale (POS) service providers. Despite the targeted nature of the spearphishing emails, the payload was the widely distributed Vawktrak banking Trojan. In addition, we found that the infrastructure used in this case overlaps with FindPOS/PoSeidon as well as Chanitor and sits amidst a cluster of la...

---

## Banking Malware Dridex Arrives via Phishing Email

**Summary:** In a recent case involving the Dridex malware, McAfee Labs found the distribution method to be typical: The malware arrives via a phishing email....

---

## Cmstar Downloader: Lurid and Enfal's New Cousin

**Summary:** In recent weeks, Unit 42 has been analyzing delivery documents used in spear-phishing attacks that drop a custom downloader used in cyber espionage attacks. This specific downloader, Cmstar, is associated with the Lurid downloader also known as ‘Enfal’. Cmstar was named for the log message ‘CM**’ used by the downloader....

---

## Spear phishing attacks against Danish chiropractors

**Summary:** CSIS has been informed about a number of targeted spear phishing attacks against Danish chiropractors. The attacks have been carried out by means of well-drafted emails that were written in flawless Danish and that were sent to carefully selected targets....

---

## KeyBase Keylogger Malware Family Exposed

**Summary:** In recent months, our team has been tracking a keylogger malware family named KeyBase that has been in the wild since February 2015. The malware comes equipped with a variety of features and can be purchased for $50 directly from the author. It has been deployed in attacks against organizations across many industries and is predominantly delivered via phishing emails....

---

## Fidelis Threat Advisory #1017: Phishing in Plain Sight

**Summary:** Fidelis Cybersecurity analysis has identified unrelated cyber criminal activity leveraging the vulnerability cited in CVE-2014-4114, which was initially exploited by advanced persistent threat (APT) actors in October 2014. Notably, some of this recent activity demonstrated actors implementing a technique that bypassed antivirus detection by saving a PowerPoint document in which malware executed once the document was opened in Slide Show presentation format. The identification of cyber crime acto...

---

## Evoltin POS Malware Attacks via Macro

**Summary:** Over the past couple of months McAfee Labs has seen an increase in the usage of macros to deliver malware. This kind of malware, as mentioned in previous posts (Dridex, Bartallex), usually arrives as an attached document within a phishing email. Recently McAfee labs came across a point-of-sale (POS) malware that spreads through malicious macros inside a doc file. This macro comes into users’ systems through a spam email with subjects such as "My Resume," "Openings," Internship," etc. and an atta...

---

## Operation Clandestine Wolf – Adobe Flash Zero-Day APT3 Phishing

**Summary:** In June, FireEye’s FireEye as a Service team in Singapore uncovered a phishing campaign exploiting an Adobe Flash Player zero-day vulnerability (CVE-2015-3113). The attackers’ emails included links to compromised web servers that served either benign content or a malicious Adobe Flash Player file that exploits CVE-2015-3113....

---

## Stealthy Cyberespionage Campaign Attacks With Social Engineering

**Summary:** The McAfee Labs research team has tracked an advanced persistent threat for the past couple of months. This group has evolved a lot in sophistication and evasion techniques to defeat detection by security products. This group has been active since at least 2014 and uses spear-phishing campaigns to target enterprises. We have observed this group targeting defense, aerospace, and legal sector companies....

---

## APT Group Wekby Leveraging Adobe Flash Exploit

**Adversary:** Wekby

**Summary:** As if the recent breach and subsequent public data dump involving the Italian company Hacking Team wasn’t bad enough, it all gets just a little bit worse. Emerging from the bowels of Hacking Team data dump was a Flash 0-day exploit (CVE-2015-5119) that was just patched today by Adobe as covered in APSB15-16. The exploit has since been added into the Angler Exploit Kit and integrated into Metasploit. However, not to be out done, APT attackers have also started leveraging the exploit in targeted s...

---

## APT Group UPS Targets US Government with HT Flash Exploit

**Adversary:** UPS

**Summary:** On July 8, 2015, Unit 42 used the AutoFocus Threat Intelligence service to locate and investigate activity consistent with a spear-phishing attack targeting the US Government. The attack exploited an Adobe Flash vulnerability that stems from the zero-day vulnerabilities exposed from this month’s Hacking Team data breach....

---

## Multiple Chinese APT Groups Quickly Use Flash Zero-Day

**Adversary:** UPS

**Summary:** The FireEye as a Service team detected independent phishing campaigns conducted by two Chinese advanced persistent threat (APT) groups that we track, APT3 and APT18. Each threat group quickly took advantage of a zero-day vulnerability (CVE-2015-5119), which was leaked in the disclosure of Hacking Team’s internal data. Adobe released a patch for the vulnerability on July 8, 2015. Before that patch was released, the groups launched phishing campaigns against multiple companies in the aerospace and...

---

## DEMONSTRATING HUSTLE - APT18 (BLOG)

**Summary:** This IOC contains indicators detailed in the blog post "Demonstrating Hustle" that can be read here: https://www.fireeye.com/blog/threat-research/2015/07/demonstrating_hustle.html. This IOC contains indicators for a spearphishing campaign carried out by APT18....

---

## PlugX Uses Legitimate Samsung Application for DLL Side-Loading

**Summary:** While threat actors using the PlugX Trojan typically leverage legitimate executables to load their malicious DLLs through a technique called DLL side-loading, Unit 42 has observed a new executable in use for this purpose. Threat actors are now using this previously unseen executable, created by Samsung, to load variants of the PlugX Trojan....

---

## Targeted Crimeware in the Midst of Indiscriminate Activity

**Summary:** Although we have observed low volume spam campaigns by some cybercriminals who have purchased MWI, we recently discovered spearphishing emails by one group using MWI to direct an attack against point-of-sale (POS) service providers. Despite the targeted nature of the spearphishing emails, the payload was the widely distributed Vawktrak banking Trojan. In addition, we found that the infrastructure used in this case overlaps with FindPOS/PoSeidon as well as Chanitor and sits amidst a cluster of la...

---

## TROJ_WERDLOD: New Banking Trojan Targets Japan

**Summary:** A new online banking malware with the same technique used in Operation Emmental has been hitting users in Japan. Detected as TROJ_WERDLOD, this new malware has been causing problems in the country since December 2014 with more than 400 confirmed victims....

---

## Trojan.Linux.Spike.A

**Summary:** Trojan.Linux.Spike.A is a Bot agent that targets the Linux platforms. The malware is also available for other architectures and platforms. It contacts a remote server, sending system information. Moreover, it receives control commands to perform different types of DoS attacks against a given target, download a file and execute it, and terminate a process....

---

## Trojanized PuTTY Software

**Summary:** In late 2013­­­–early 2014, a compromised FTP client dubbed “StealZilla,” based off the open source FileZilla FTP client was discovered. The attackers modified a few lines of code, recompiled the program, and disbursed the trojanized version on compromised web servers. This new attack appears to involve the same actors who reused the same techniques to alter the source code of the widely used open source Telnet/SSH client, PuTTY, and used their network of compromised web servers to serve up simi...

---

## A New UAC Bypass Method that Dridex Uses

**Summary:** Dridex is a banking trojan, which is a bot that communicates with a C&C server through HTTP. This variant uses a new UAC bypass method that has been used by the Dridex malware since December, 2014....

---

## e-Banking Trojan Retefe still spreading in Switzerland

**Summary:** In July 2014, Trend Micro published a report about a threat called Retefe, an ebanking Trojan that is targeting financial institutions in Switzerland, Austria, Sweden and Japan. In fact, Retefe is already around since November 2013. Back then, MELANI already took appropriate action together with the affected financial institutions and ISPs in Switzerland to mitigate the threat. However, Retefe is still being distributed in recent spam campaigns, targeting Swiss Internet users....

---

## Dyre Spreading Using Code-Signing Certificates, HTTPS

**Summary:** ThreatTrack Security Labs researchers have confirmed the credential-stealing Trojan Dyre  is using a new dropper — and a valid digital certificate — to carry out its dirty work over HTTPS connections....

---

## Backdoor.Darpapox

**Summary:** Backdoor.Darpapox is a Trojan horse that opens a back door and steals information from the compromised computer. It may also download potentially malicious files....

---

## Unusual Exploit Kit Targets Chinese Users,2

**Summary:** This article will discuss the malware delivered from that exploit kit. The malware, which has been identified by many vendors on VirusTotal, has been labeled by our researchers as Trojan.Chinad or just “Chinad” as an alternative (short) label....

---

## Stegoloader: A Stealthy Information Stealer

**Summary:** Malware authors are evolving their techniques to evade network and host-based detection mechanisms. Stegoloader could represent an emerging trend in malware: the use of digital steganography to hide malicious code. The Stegoloader malware family (also known as Win32/Gatak.DR and TSPY_GATAK.GTK despite not sharing any similarities with the Gataka banking trojan) was first identified at the end of 2013 and has attracted little public attention. Dell SecureWorks Counter Threat Unit(TM) (CTU) resear...

---

## Dyre: Emerging threat on financial fraud landscape

**Summary:** A significant upsurge in activity over the past year has seen Dyre emerge as one of the most dangerous financial Trojans, capable of defrauding customers of a wide range of financial institutions across multiple countries.

Dyre is a highly developed piece of malware, capable of hijacking all three major web 
browsers and intercepting internet banking sessions in order to harvest the victim’s 
credentials and send them to the attackers. 

Dyre is a multi-pronged threat and is often used to downl...

---

## New Dridex infection vector identified

**Summary:** Malware authors can sometimes be creative in order to manipulate their human targets on the one hand and to circumvent security products, too. The experts of G DATA’s SecurityLabs analyzed a specially crafted Microsoft Word document the attackers used to install a rather famous banking Trojan called Dridex. This malicious document connects to a perfectly legitimate website to download the final payload. We assume that these two elements were chosen to trick security products. This scam is used m...

---

## US Healthcare Organizations Most Affected by Stegoloader Trojan

**Summary:** Most victims of the Stegoloader Trojan, which has recently been making its rounds in the news, are observed to come from healthcare organizations in North America.  The malware known as TROJ_GATAK has been active since 2012 and uses steganography techniques to hide components in .PNG files....

---

## Dyre emerges as main financial Trojan threat

**Summary:** The Dyre financial Trojan has emerged over the past year to become one of the most potent financial fraud tools in operation. Dyre is configured to defraud the customers of more than 1,000 banks and other companies worldwide. Consumers in English-speaking countries, in particular the US and UK, are most at risk, since this is where the largest numbers of targeted banks are located....

---

## IRC Botnets alive, effective & evolving

---

## Dyre Botnet Using Malicious Microsoft Word Macros

**Summary:** The Dyre group, a major malware spam producer, has changed their initial malware dropper to utilize Microsoft Word document macros instead of the usual executable types, such as .exe files contained in a .zip....

---

## Bedep Ad-Fraud Botnet Analysis

**Summary:** Following on from our post on Angler EK we are going to expose the mechanics behind the Bedep ad-fraud malware. Recently Bedep has been observed as the payload dropped by the Anger EK in a series of malvertising campaigns. These campaigns have lead to a rapid rise in the rate of Bedep infections, with Arbour Networks observing just above 80K infections over a 3-day period....

---

## Blue DDoS Botnet

**Summary:** Indicators about some panels hosting the DDoS Blue Botnet...

---

## Linux/Moose

**Summary:** Linux/Moose is a malware family that primarily targets Linux-based consumer routers but that can infect other Linux-based embedded systems in its path. The compromised devices are used to steal unencrypted network traffic and offer proxying services to the botnet operator. In practice, these capabilities are used to steal HTTP Cookies on popular social network sites and perform fraudulent actions such as non-legitimate "follows", "views" and "likes" on such sites....

---

## Compromised Turkish Government Web site leads to malware

**Summary:** An interesting Web site infection, this time affecting a Web server belonging to the Turkish government, where the cybercriminals behind the campaign have uploaded a malware-serving fake ‘DivX plug-in Required!” Facebook-themed Web page. Once socially engineered users execute the malware variant, their PCs automatically join the botnet operated by the cybercriminals behind the campaign....

---

## Disrupting an Adware-serving Skype Botnet

**Summary:** In the early days of malware, we all remember analyzing samples of IRC botnets that were relatively simple, where the malware would connect to a random port running IRC, joining the botnet and waiting for commands from their leader. In this day and age, it’s slightly different. Whereas botnets previously had to run on systems that attackers owned or had compromised, now bots can run on Skype and other cloud-based chat programs, providing an even lower-cost alternative for attackers....

---

## Exposedbotnets: probably Pony domains

---

## Gamarue dropping Lethic bot

**Summary:** The Gamarue (aka Andromeda) botnet is a highly modular botnet family that allows attackers to take complete control of an infected system and perform a range of malicious activity by downloading additional payloads. In this blog, we will cover a recent Gamarue infection that we looked at, which downloads and installs the Lethic bot on an infected system....

---

## The Elastic Botnet

**Summary:** Novetta has collected and shares within this report evidence that suggests multiple actors,
possibly working independently while sharing information between themselves, are exploiting the Elasticsearch vulnerability primarily to establish widespread DDoS botnet infrastructures. Using both the Elknot and BillGates DDoS malware, these attackers have continued to infect vulnerable Elasticsearch servers in order to enhance their DDoS capabilities. The continuous scanning and exploitation of Elastics...

---

## Dridex + dropbox

**Summary:** Botnets continually send out malicious spam (malspam).  As mentioned in previous diaries, we see botnet-based malspam delivering Dridex and Dyre malware almost every day [1, 2].  Recently, someone sent us a malicious Word document from what appeared to be Dridex malspam on Tuesday 2015-06-16.  (Thanks, Wayne... You know who you are!)  Unfortunately, while investigating the malware, I could not generate the full range of infection traffic.  Otherwise, the traffic follows the same general patterns...

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

<!-- CHUNK: Part 3 - Cisco XDR Threat Intelligence -->
# Part 3: Cisco XDR Threat Intelligence

Enriched threat intelligence from Cisco XDR (Extended Detection and Response).

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---

---
