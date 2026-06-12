# VolumeShadowSnapshotDeleted Investigation

## Objective

Investigate deletion of Volume Shadow Copies detected by CrowdStrike Falcon. This activity is frequently observed during ransomware execution, destructive malware activity, and attacker attempts to inhibit system recovery.

---

## CrowdStrike Detection

### Detection Name

VolumeShadowSnapshotDeleted

### MITRE ATT&CK

* T1490 - Inhibit System Recovery

### Risk

HIGH

### Common Commands

```cmd
vssadmin delete shadows /all /quiet

wmic shadowcopy delete

powershell.exe Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}

diskshadow.exe
```

---

## Initial Triage

### Detection Summary

Review:

* Detection Severity
* Tactic
* Technique
* Triggering Process
* Hostname
* Username
* Detection Time

Determine:

* Single endpoint or multiple endpoints
* First occurrence or recurring activity
* Detection confidence

---

## Falcon Investigation Workflow

### 1. Process Rollup

Review Process Rollup information.

Collect:

* Image Filename
* Command Line
* SHA256
* MD5
* User Context
* Integrity Level
* Parent Process
* Grandparent Process

Questions:

* Is vssadmin.exe legitimate?
* Was execution user initiated?
* Is command obfuscated?
* Is execution occurring during business hours?

---

### 2. Process Ancestry

Review complete process lineage.

Example:

```text
explorer.exe
 └── cmd.exe
      └── vssadmin.exe
```

or

```text
winword.exe
 └── powershell.exe
      └── cmd.exe
           └── vssadmin.exe
```

Red Flags:

* Office spawning PowerShell
* Outlook spawning cmd.exe
* Browser spawning PowerShell
* Multiple LOLBins chained together

Investigate:

* Parent Process
* Grandparent Process
* Root Process

Determine attack origin.

---

### 3. Event Search

Pivot to Event Search.

Search for:

* ProcessRollup2
* SyntheticProcessRollup2
* DetectionSummaryEvent

Review:

* Process execution history
* Child processes
* Additional suspicious binaries
* Timeline progression

Questions:

* Was shadow copy deletion first action?
* Was malware executed before deletion?
* Did encryption activity follow?

---

### 4. Detection Summary Event

Review:

* Detection Description
* Trigger Logic
* Associated Indicators
* Related Behaviors

Collect:

* Falcon Detection ID
* Host ID
* User SID
* Device Information

---

### 5. Command Line Analysis

Review exact command executed.

Examples:

```cmd
vssadmin delete shadows /all /quiet
```

```cmd
wmic shadowcopy delete
```

```cmd
powershell.exe -ExecutionPolicy Bypass
```

Determine:

* Administrative maintenance?
* Backup software?
* Malicious execution?

---

### 6. File Activity Review

Investigate:

* Mass file modifications
* Large volume file renames
* File extension changes
* Encryption indicators

Common ransomware indicators:

```text
.locked
.crypt
.encrypted
.lockbit
.blackcat
```

---

### 7. Network Activity

Review Falcon telemetry.

Check:

* External IP connections
* TOR activity
* C2 communications
* Large outbound transfers

Collect:

* Source IP
* Destination IP
* Domain
* Port

Determine:

* Data exfiltration
* Command and Control

---

### 8. User Investigation

Validate:

* Interactive Logon
* RDP Session
* Service Account
* Scheduled Task Execution

Questions:

* Did the user launch activity?
* Is account compromised?
* Is privilege escalation observed?

---

### 9. Persistence Review

Investigate:

* Registry Run Keys
* Scheduled Tasks
* Startup Folder
* New Services
* WMI Event Subscriptions

MITRE:

* T1547

---

### 10. Lateral Movement Review

Look for:

* PsExec
* SMB
* WMI
* WinRM
* Remote Services

MITRE:

* T1021

Questions:

* Is activity isolated?
* Has attacker moved laterally?

---

## Scope Determination

Determine:

### Host Scope

* Single endpoint
* Multiple endpoints

### User Scope

* Single account
* Multiple accounts

### Network Scope

* Single segment
* Enterprise-wide

---

## False Positive Validation

Validate:

* Backup software
* Storage migration
* System administration activity
* Infrastructure maintenance

Examples:

* Veeam
* Commvault
* BackupExec

---

## Containment Actions

### Immediate

* Isolate Host
* Disable Account
* Revoke Sessions
* Block Indicators

### Follow-Up

* Reset Credentials
* Hunt Enterprise-Wide
* Review EDR Coverage
* Validate Backups

---

## Indicators of True Positive

* Shadow copy deletion
* PowerShell execution
* LSASS access
* Scheduled task creation
* New service creation
* Mass file encryption
* External C2 communication

---

## Analyst Verdict

### True Positive

Ransomware activity confirmed.

### Suspicious

Further investigation required.

### False Positive

Authorized administrative activity verified.
