# Impossible Travel Investigation

## Objective

Determine whether a user account was accessed from geographically impossible locations.

## Data Sources

- Microsoft Entra ID
- Microsoft Sentinel
- Defender XDR

## Investigation Steps

### Step 1

Review login activity.

Collect:

- Username
- Source IP
- Country
- Timestamp
- Device

### Step 2

Validate:

- VPN usage
- Corporate proxy
- Mobile roaming

### Step 3

Review authentication activity.

Check:

- MFA completion
- New devices
- Risky sign-ins

### Step 4

Look for compromise indicators.

Examples:

- Password changes
- Mailbox rule creation
- Large file downloads

## Containment

- Revoke sessions
- Force password reset
- Enable MFA review
- Block suspicious IPs

## MITRE ATT&CK

- T1078 Valid Accounts
