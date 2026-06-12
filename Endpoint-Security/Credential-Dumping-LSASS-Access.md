# Credential Dumping - LSASS Access Investigation

## Objective

Investigate potential credential dumping activity detected by CrowdStrike Falcon. Credential dumping is commonly performed by threat actors to extract passwords, NTLM hashes, Kerberos tickets, and authentication material from memory.

---

## CrowdStrike Detection

### Detection Name

Credential Dumping

### MITRE ATT&CK

* T1003 - OS Credential Dumping

### Risk

CRITICAL

---

## Why This Matters

Credential dumping is often one of the first actions performed after privilege escalation.

Compromised credentials may lead to:

* Privilege Escalation
* Lateral Movement
* Domain Compromise
* Ransomware Deployment

---

## Common Tools

### Mimikatz

```cmd
mimikatz.exe
sekurlsa::logonpasswords
```

### ProcDump

```cmd
procdump.exe -ma lsass.exe
```

### Rundll32

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump
```

### Task Manager Dump

```text
Task Manager
Create Dump File
```

---

## Initial Triage

### Detection Summary

Review:

* Detection Severity
* Detection Timestamp
* Hostname
* Username
* Detection Description
* Tactic
* Technique

Determine:

* Workstation or Server
* Privileged User Involved
* Single Host or Multiple Hosts

---

## Falcon Investigation Workflow

### 1. Detection Details

Collect:

* Detection ID
* Hostname
* Username
* Process Name
* SHA256
* Command Line
* Detection Trigger

Questions:

* What process triggered the detection?
* Was LSASS accessed?
* Was a dump file created?

---

### 2. Process Rollup2 Analysis

Review:

* Process Name
* Parent Process
* Grandparent Process
* SHA256
* MD5
* Integrity Level
* User Context

Look for:

```text
mimikatz.exe
procdump.exe
rundll32.exe
powershell.exe
cmd.exe
```

---

### 3. Process Ancestry Analysis

Review complete process lineage.

Example:

```text
explorer.exe
 └── cmd.exe
      └── procdump.exe
```

Suspicious Example:

```text
winword.exe
 └── powershell.exe
      └── mimikatz.exe
```

Suspicious Example:

```text
outlook.exe
 └── powershell.exe
      └── rundll32.exe
```

Red Flags:

* Office spawning PowerShell
* PowerShell spawning Mimikatz
* Browser spawning dump utilities

---

### 4. LSASS Access Investigation

Validate:

* Was lsass.exe accessed?
* Was memory read?
* Was a dump file generated?

Review:

* Process Handle Access
* Memory Reads
* Process Injection Attempts

Questions:

* Read-only access?
* Full memory dump?
* Credential extraction confirmed?

---

### 5. Event Search Investigation

Pivot into Event Search.

Review:

### ProcessRollup2

Collect:

* Additional executions
* Child processes
* Related activity

### SyntheticProcessRollup2

Review:

* Full execution timeline
* Process relationships

### DetectionSummaryEvent

Review:

* Detection logic
* Detection trigger
* Associated behaviors

---

### 6. Command Line Analysis

Review complete command line.

Examples:

```cmd
procdump.exe -ma lsass.exe
```

```cmd
rundll32.exe comsvcs.dll MiniDump
```

```cmd
powershell.exe Invoke-Mimikatz
```

Investigate:

* Encoded Commands
* Obfuscation
* Download Activity

---

### 7. File Creation Analysis

Review:

* Memory Dump Files
* Newly Created Files
* Temporary Files

Common Locations:

```text
C:\Temp
C:\Users\Public
C:\Windows\Temp
```

Common Extensions:

```text
.dmp
.bin
.zip
```

Questions:

* Was dump archived?
* Was dump compressed?
* Was dump moved elsewhere?

---

### 8. User Context Review

Determine:

* Interactive User
* Service Account
* Administrator Account
* SYSTEM Context

Questions:

* Is user expected to perform debugging?
* Is account privileged?
* Is account compromised?

---

### 9. Network Activity Investigation

Review Falcon telemetry.

Collect:

* Source IP
* Destination IP
* Domain
* Port

Investigate:

* External communication
* Data exfiltration
* Command and Control

Questions:

* Was dump file uploaded?
* Was data transferred externally?

---

### 10. Privilege Escalation Review

Investigate:

* UAC Bypass
* Token Manipulation
* Local Administrator Membership

MITRE:

* T1068
* T1134

---

### 11. Lateral Movement Investigation

Review:

* PsExec
* SMB
* WinRM
* WMI
* RDP

MITRE:

* T1021

Questions:

* Were credentials used elsewhere?
* Has attacker moved laterally?

---

### 12. Active Directory Investigation

Review:

* Domain Admin Usage
* Service Account Activity
* Kerberos Events

Look for:

```text
4624
4625
4672
4768
4769
```

Questions:

* Domain Admin exposure?
* Golden Ticket activity?
* Kerberoasting indicators?

---

## Scope Determination

### Host Scope

* Single Endpoint
* Multiple Endpoints

### User Scope

* Single User
* Multiple Users

### Credential Scope

* Local Accounts
* Domain Accounts
* Privileged Accounts

---

## False Positive Validation

Validate:

### Security Tools

* CrowdStrike Falcon
* Defender
* EDR Testing

### Administrative Activity

* Memory Forensics
* Incident Response
* Approved Security Assessments

Questions:

* Authorized security activity?
* Approved testing?
* IR engagement in progress?

---

## Containment Actions

### Immediate

* Isolate Endpoint
* Disable User Account
* Revoke Active Sessions
* Block Indicators

### Follow-Up

* Reset Credentials
* Reset Privileged Accounts
* Threat Hunt Enterprise-Wide
* Review AD Exposure

---

## Indicators of True Positive

* LSASS Access
* Memory Dump Creation
* Mimikatz Execution
* ProcDump Usage
* Credential Extraction
* Lateral Movement
* External Data Transfer

---

## Analyst Verdict

### True Positive

Credential dumping confirmed.

### Suspicious

Further investigation required.

### False Positive

Authorized security activity validated.
