# MFA Fatigue Attack Investigation

## Objective

Investigate repeated MFA prompts that may indicate an MFA fatigue attack.

## Data Sources

* Microsoft Entra ID
* Microsoft Sentinel
* Defender XDR

## Investigation Steps

### Step 1

Review MFA logs.

### Step 2

Identify repeated push notifications.

### Step 3

Determine if user eventually approved a request.

### Step 4

Review login source IP and device.

### Step 5

Validate account compromise indicators.

## Containment

* Revoke sessions
* Reset password
* Enforce phishing-resistant MFA

## MITRE ATT&CK

* T1078 Valid Accounts
