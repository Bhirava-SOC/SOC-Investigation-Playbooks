# Phishing Investigation Playbook

## Objective

Investigate reported phishing emails and determine whether malicious activity occurred.

## Investigation Steps

### 1. Collect Email Details

- Sender
- Recipient
- Subject
- URLs
- Attachments

### 2. Verify Sender

- SPF
- DKIM
- DMARC

### 3. Analyze URLs

- Domain reputation
- Redirects
- Domain age

### 4. Analyze Attachments

- Hash reputation
- Sandbox analysis

### 5. Determine Impact

- Link clicked?
- Credentials entered?
- Malware executed?

## Containment

- Block sender
- Quarantine email
- Reset credentials if compromised

## MITRE ATT&CK

T1566.001
T1566.002
