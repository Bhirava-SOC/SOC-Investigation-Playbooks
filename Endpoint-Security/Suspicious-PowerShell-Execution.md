# Suspicious PowerShell Execution Investigation

## Objective

Investigate suspicious PowerShell activity detected by CrowdStrike Falcon. PowerShell is commonly abused by attackers for malware execution, credential theft, lateral movement, persistence, and command-and-control operations.

---

## CrowdStrike Detection

### Detection Name

Suspicious PowerShell Execution

### MITRE ATT&CK

* T1059.001 - PowerShell

### Risk

HIGH

---

## Common Suspicious Commands

### Encoded Commands

```powershell
powershell.exe -enc
powershell.exe -encodedcommand
```

### Hidden Window Execution

```powershell
powershell.exe -w hidden
```

### Execution Policy Bypass

```powershell
powershell.exe -ExecutionPolicy Bypass
```

### Download and Execute

```powershell
IEX (New-Object Net.WebClient).DownloadString()
```

### Base64 Encoded Payloads

```powershell
FromBase64String
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
* Technique
* Tactic

Determine:

* Single host or multiple hosts
* User initiated or automated execution
* First occurrence or recurring activity

---

## Falcon Investigation Workflow

### 1. Detection Details

Collect:

* Detection ID
* Hostname
* User
* SHA256
* Command Line
* File Path

Validate:

* Detection Confidence
* Detection Trigger
* Associated Behaviors

---

### 2. Process Rollup2 Analysis

Review:

* Process Name
* Command Line
* Parent Process
* SHA256
* MD5
* Integrity Level
* User Context

Questions:

* What launched PowerShell?
* Was the command encoded?
* Was it launched interactively?

---

### 3. Process Ancestry Analysis

Review full process tree.

Normal Example:

```text
explorer.exe
 └── powershell.exe
```

Suspicious Example:

```text
outlook.exe
 └── powershell.exe
```

Suspicious Example:

```text
winword.exe
 └── powershell.exe
```

Suspicious Example:

```text
chrome.exe
 └── powershell.exe
```

Red Flags:

* Office spawning PowerShell
* Browser spawning PowerShell
* Multiple LOLBins chained together
* PowerShell spawning cmd.exe

---

### 4. Command Line Analysis

Review complete command line.

Look for:

```text
-enc
-encodedcommand
-w hidden
-nop
-ExecutionPolicy Bypass
DownloadString
FromBase64String
Invoke-WebRequest
Invoke-Expression
```

Questions:

* Is command obfuscated?
* Is payload encoded?
* Is PowerShell downloading content?

---

### 5. Script Content Review

Determine:

* Script purpose
* Network communication
* File downloads
* Registry modifications
* Persistence mechanisms

Indicators:

* Base64 strings
* Long encoded payloads
* Obfuscation techniques

---

### 6. Event Search Investigation

Pivot into Event Search.

Review:

* ProcessRollup2
* SyntheticProcessRollup2
* DetectionSummaryEvent

Investigate:

* Child Processes
* Additional PowerShell executions
* Timeline progression

---

### 7. Child Process Review

Determine whether PowerShell spawned:

```text
cmd.exe
rundll32.exe
mshta.exe
regsvr32.exe
certutil.exe
```

Red Flags:

* PowerShell → cmd.exe
* PowerShell → mshta.exe
* PowerShell → rundll32.exe

---

### 8. Network Activity Investigation

Review Falcon telemetry.

Collect:

* Source IP
* Destination IP
* Domain
* Port
* Protocol

Determine:

* External communication
* Command and Control traffic
* Malware downloads

Look for:

* Newly registered domains
* Known malicious IPs
* TOR nodes

---

### 9. Persistence Investigation

Review:

* Registry Run Keys
* Startup Folder
* Scheduled Tasks
* Services
* WMI Event Subscriptions

MITRE:

* T1547

---

### 10. Credential Access Investigation

Determine whether PowerShell attempted:

* LSASS Access
* Credential Dumping
* Token Theft

MITRE:

* T1003

---

### 11. Lateral Movement Investigation

Review:

* PsExec Activity
* SMB Connections
* Remote Services
* WinRM

MITRE:

* T1021

---

## Scope Determination

### Host Scope

* Single Host
* Multiple Hosts

### User Scope

* Single User
* Multiple Users

### Enterprise Scope

* Isolated Event
* Widespread Activity

---

## False Positive Validation

Validate:

* SCCM Activity
* Intune Activity
* Administrative Scripts
* IT Operations Automation
* Monitoring Tools

Questions:

* Is execution expected?
* Is script signed?
* Is source trusted?

---

## Containment Actions

### Immediate

* Isolate Endpoint
* Kill Malicious Process
* Block Indicators
* Revoke Sessions

### Follow-Up

* Reset Credentials
* Threat Hunt Environment
* Review Detection Coverage
* Create Detection Rule

---

## Indicators of True Positive

* Encoded Commands
* Hidden Window Execution
* DownloadString Usage
* External Network Connections
* Child Process Creation
* Persistence Mechanisms
* Credential Access Attempts

---

## Analyst Verdict

### True Positive

Malicious PowerShell activity confirmed.

### Suspicious

Further investigation required.

### False Positive

Authorized administrative activity validated.
