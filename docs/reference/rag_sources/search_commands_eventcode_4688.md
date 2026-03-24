# Windows Event Code 4688 and PowerShell Process Monitoring

**Document Type**: Search Reference & Security Monitoring Guide
**Audience**: Security Analysts, SOC Engineers, Threat Hunters
**Topics**: Windows Process Execution, PowerShell Monitoring, Event Code 4688, Malicious Process Detection
**Keywords**: Event Code 4688, PowerShell, process execution, WMI, command line analysis, process monitoring, security detection

**Quick Links:**
- Windows Process Execution Event (4688): https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- PowerShell Logging: https://docs.splunk.com/Documentation/UBA/latest/GetDataIn/AddPowerShellMonitoring
- Endpoint Data Model: https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint

**Description:** Search queries and analysis techniques for monitoring Windows process execution and detecting malicious PowerShell activity

**Last Updated:** 2025-11-25

## Search Keywords & Index Terms

**This document covers:** Event Code 4688, PowerShell process execution, malicious process detection, WMI activity, process command line, process monitoring, Windows security event analysis

**Find this document by searching for:** EventCode 4688, PowerShell detection, malicious process, process execution monitoring, Windows process audit, command line analysis

---

## Overview

Windows Event Code 4688 logs process creation events. This is critical for detecting malicious activity including:

- PowerShell with encoded commands
- WMI (Windows Management Instrumentation) execution
- Process injection
- Suspicious command lines

---

## Basic 4688 Search

### Simple Process Execution Query

```spl
index=winevents EventCode=4688
| stats count by _time, host, user, New_Process_Name, Process_Command_Line
| table _time host user New_Process_Name Process_Command_Line count
```

### Filter Out Legitimate PowerShell Activity

```spl
index=winevents EventCode=4688
| search Process_Command_Line !="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe*&*{}*"
| stats count by _time, host, user, New_Process_Name, Process_Command_Line
| table _time host user New_Process_Name Process_Command_Line count
```

---

## PowerShell-Specific Searches

### Detect All PowerShell Execution

```spl
| tstats summariesonly=false allow_old_summaries=true fillnull_value=null count 
  min(_time) as firstTime max(_time) as lastTime 
from datamodel=Endpoint.Processes 
where (Processes.process_name=pwsh.exe 
   OR Processes.process_name=powershell.exe 
   OR Processes.process_name=powershell_ise.exe 
   OR Processes.original_file_name=pwsh.dll 
   OR Processes.original_file_name=PowerShell.EXE 
   OR Processes.original_file_name=powershell_ise.EXE) 
by Processes.user, Processes.process_name, Processes.process, 
   Processes.parent_process_name, Processes.original_file_name, 
   Processes.dest, Processes.process_id
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) 
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
```

### Detect Suspicious PowerShell Patterns

Exclude known legitimate patterns and look for suspicious ones:

```spl
| tstats summariesonly=false allow_old_summaries=true fillnull_value=null count 
  min(_time) as firstTime max(_time) as lastTime 
from datamodel=Endpoint.Processes 
where (Processes.process_name=powershell.exe)
by Processes.user, Processes.process_name, Processes.process, 
   Processes.parent_process_name, Processes.dest, Processes.process_id
| search NOT Processes.process IN ("*powershell.exe*&*{}")
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime)
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime)
| table firstTime lastTime host user process_name process
```

---

## WMI Execution Detection

### Detect WMI Process Execution

```spl
index=winevents new_process_name="*wmi*"
| search Process_Command_Line !="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe*&*{}*"
| stats count by _time, host, user, New_Process_Name, Process_Command_Line
| table _time host user New_Process_Name Process_Command_Line count
```

### Combined 4688 with WMI Filter

```spl
| tstats summariesonly=false allow_old_summaries=true fillnull_value=null count 
from datamodel=Endpoint.Processes 
where Processes.process_name="wmic.exe" OR Processes.process_id=4688
  AND Processes.process !="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe*&*{}*"
by _time, host, user, Processes.process_name, Processes.process
| table _time host user Processes.process_name Processes.process
```

---

## Advanced Detection with Macros

### Using Security Content Macros

For production deployments, use standardized macros from Splunk security content:

```spl
| tstats `security_content_summariesonly` 
  count min(_time) as firstTime max(_time) as lastTime 
from datamodel=Endpoint.Processes 
where `process_powershell` 
by Processes.user, Processes.process_name, Processes.process, 
   Processes.parent_process_name, Processes.original_file_name, 
   Processes.dest, Processes.process_id
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`  
| `malicious_powershell_process___encoded_command_filter`
```

---

## Test Search with Sample Data

### Create Sample Process Execution Data

```spl
| makeresults count=2
| eval _time=strftime(now(), "%Y-%m-%d %H:%M:%S"), 
        host="host1", 
        user="user1", 
        New_Process_Name="powershell.exe", 
        process="\"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe\" & {}"
| append [| makeresults count=5 
          | eval _time=strftime(now(), "%Y-%m-%d %H:%M:%S"), 
                  host="host2", 
                  user="user2", 
                  New_Process_Name="powershell.exe", 
                  process="Invoke-WebRequest"]
| search NOT process IN ("*powershell.exe*&*{}","*xxx*")
| table _time host user New_Process_Name process
```

---

## Event Code 4688 Fields

| Field | Description |
|-------|-------------|
| **EventCode** | Should be 4688 for process execution |
| **New_Process_Name** | Full path to new process executable |
| **New_Process_ID** | Process ID (in hex format) |
| **Creator_Process_Name** | Parent process name |
| **Creator_Process_ID** | Parent process ID |
| **Process_Command_Line** | Full command line executed |
| **New_Process_Command_Line** | Command line of new process |
| **Target_User_Name** | User account that created process |
| **Creator_User_Name** | User that initiated the process |

---

## Red Flags for Malicious Activity

Look for these indicators in process execution:

### PowerShell Indicators
- 🚩 PowerShell with `-EncodedCommand` parameter
- 🚩 PowerShell with `-NoProfile -WindowStyle Hidden`
- 🚩 PowerShell spawning from Office applications
- 🚩 PowerShell with base64 encoded scripts

### WMI Indicators
- 🚩 WMI calls from unusual parent processes
- 🚩 `wmic.exe` used to execute remote code
- 🚩 `wmic.exe` with suspicious XSL scripts

### General Process Indicators
- 🚩 Processes in TEMP or ProgramData directories
- 🚩 Processes with unusual parent processes
- 🚩 Processes spawned by Office applications
- 🚩 Living-off-the-land (LOLBin) execution

---

## Best Practices for 4688 Monitoring

1. **Enable Auditing**: Ensure "Audit Process Creation" is enabled on all Windows systems
2. **Command Line Auditing**: Enable "Include command line in process creation events"
3. **Monitor PowerShell**: Pay special attention to PowerShell execution
4. **Track Parent-Child Relationships**: Monitor which processes spawn which
5. **Establish Baselines**: Know what's normal in your environment
6. **Alert on Anomalies**: Create alerts for suspicious patterns
7. **Tune False Positives**: Exclude legitimate administrative activity
8. **Correlate with Other Events**: Combine with network and file events

---

## Related Topics

- Windows Security Event Logging
- PowerShell Security Monitoring
- Endpoint Detection and Response (EDR)
- Process Injection Detection
- Lateral Movement Detection
- Threat Hunting with Process Execution
- Living-off-the-Land (LOLBin) Detection
