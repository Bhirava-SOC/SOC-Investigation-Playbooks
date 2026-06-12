# Password Spray Investigation

## Objective

Identify attempts to gain unauthorized access using common passwords across multiple accounts.

## Alert Sources

- Microsoft Entra ID
- Microsoft Sentinel
- QRadar
- Defender XDR

## Indicators

- Multiple failed logins
- Same source IP
- Multiple usernames targeted
- Authentication anomalies

## Investigation Steps

### Step 1 - Identify Source

Collect:

- Source IP
- Geolocation
- User Agent

### Step 2 - Review Targeted Accounts

Determine:

- Number of accounts targeted
- Privileged accounts affected
- Successful authentications

### Step 3 - Validate Risk

Check:

- MFA status
- Risky sign-ins
- Recent password changes

### Step 4 - Scope Impact

Determine:

- Compromised accounts
- Lateral movement indicators
- Additional suspicious activity

## Containment

- Block malicious IP
- Force password reset
- Revoke sessions
- Review MFA enrollment

## MITRE ATT&CK

- T1110.003 Password Spraying
