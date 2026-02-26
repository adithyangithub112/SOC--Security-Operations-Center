# 1. Introduction to SIEM Detection Rules

A detection rule in a SIEM is a logical condition that monitors logs and triggers an alert when suspicious activity matches defined criteria.

Rules are created based on:

1. Security use cases
2. Threat intelligence
3. Compliance requirements
4. Organizational risk profile

A well-designed rule should:

- Detect real threats
- Minimize false positives
- Be clear and testable
- Include context (who, what, when, where)

---

# A) Creating Detection Rules Based on Use Cases

## 1. What is a Use Case?

A use case describes a specific security scenario you want to detect.

Examples:

1. Multiple failed login attempts (Brute force attack)
2. Internal host scanning multiple ports (Port scan)
3. Malware detected by endpoint
4. Privilege escalation activity
5. Login from unusual country

---

## 2. Steps to Create a Detection Rule

### Step 1: Define the Objective

- What threat are you detecting?
- What systems are involved?
- What logs are required?

Example:

Detect brute-force attempts against Windows servers.

---

### Step 2: Identify Required Log Sources

- Windows Security logs (Event ID 4625 – failed login)
- Firewall logs
- EDR alerts

---

### Step 3: Define Trigger Conditions

- Threshold-based (e.g., 10 failed logins in 5 minutes)
- Pattern-based (e.g., sequential port access)
- Signature-based (e.g., known malware hash)

---

### Step 4: Define Alert Conditions

- Set severity level
- Define time window
- Decide correlation logic

---

### Step 5: Test and Validate

- Simulate attack
- Check if alert triggers
- Adjust thresholds if necessary

---

# B) Practice Writing Rules

# 1. Brute Force Detection Rule

## Use Case:

Detect multiple failed login attempts from a single IP.

### Required Logs:

- Windows Security Event ID 4625
- Linux authentication logs
- VPN logs

### Example Rule Logic:

1. Filter events:
    - Event type = Failed Login
2. Group by:
    - Source IP
3. Time window:
    - 5 minutes
4. Condition:
    - Count ≥ 10

### Logical Expression (Generic):

IF failed_login_count FROM same_source_ip >= 10 WITHIN 5 minutes

THEN generate alert (Severity: Medium/High)

### Explanation:

Multiple failed attempts in a short time may indicate:

- Password guessing
- Credential stuffing
- Automated brute-force attack

---

# 2. Port Scan Detection Rule

## Use Case:

Detect a host scanning multiple ports on a target.

### Required Logs:

- Firewall logs
- IDS/IPS logs

### Example Rule Logic:

1. Filter:
    - Connection attempts
2. Group by:
    - Source IP
3. Condition:
    - Access to ≥ 20 different destination ports
4. Time window:
    - 2 minutes

### Logical Expression:

IF source_ip connects to 20+ different destination_ports

WITHIN 2 minutes

THEN trigger port scan alert

### Explanation:

Attackers often scan open ports before exploitation. Rapid connection attempts across many ports indicate reconnaissance activity.

---

# 3. Malware Detection Rule

## Use Case:

Detect malware identified by endpoint protection.

### Required Logs:

- EDR alerts
- Antivirus logs

### Example Rule Logic:

1. Filter:
    - Event category = Malware detected
2. Condition:
    - Severity = High OR file quarantined
3. Optional:
    - Hash matches known malicious hash

### Logical Expression:

IF malware_detection_event = TRUE

AND severity = High

THEN generate alert (Severity: Critical)

### Explanation:

This rule detects confirmed malware presence on endpoint systems and triggers immediate response.

---

# C) Tuning Rules to Minimize False Positives

False positives reduce SOC efficiency. Tuning improves accuracy.

---

## 1. Adjust Thresholds

Example:

Instead of:

- 5 failed logins in 5 minutes

Change to:

- 10 failed logins in 5 minutes

This reduces alerts from normal user mistakes.

---

## 2. Exclude Trusted Sources

Exclude:

- Internal vulnerability scanner IP
- IT admin workstation
- Monitoring systems

Example:

IF source_ip NOT IN approved_scanner_list

---

## 3. Add Context Conditions

Instead of:

- Any failed login

Use:

- Failed login + outside business hours
- Failed login + privileged account

This increases rule precision.

---

## 4. Whitelisting

Add known:

- Service accounts
- Backup servers
- Automated scripts

But:

Whitelisting must be carefully managed to avoid blind spots.

---

## 5. Baseline Normal Behavior

Analyze:

- Normal login frequency
- Typical user behavior
- Usual traffic volume

Set thresholds slightly above baseline.

---

# D) 5 Example Rule Logics with Explanations

---

## Rule 1: Brute Force Attempt

Condition:

- 15 failed logins from same IP
- Within 10 minutes
- Targeting same user account

Alert:

High Severity

Explanation:

Indicates targeted password guessing attack.

---

## Rule 2: Account Lockout Monitoring

Condition:

- Event ID = Account Lockout
- More than 3 lockouts in 10 minutes

Alert:

Medium Severity

Explanation:

Multiple account lockouts could indicate brute force attempts or password spraying.

---

## Rule 3: Internal Port Scan

Condition:

- Internal IP connects to 50 different hosts
- Within 5 minutes

Alert:

High Severity

Explanation:

May indicate compromised machine performing lateral movement or reconnaissance.

---

## Rule 4: Suspicious Privilege Escalation

Condition:

- User added to Administrator group
- Outside business hours
- Performed by non-IT account

Alert:

Critical

Explanation:

Unauthorized privilege escalation is a high-risk activity.

---

## Rule 5: Malware Execution Behavior

Condition:

- Process spawned from temporary directory
- Followed by outbound connection
- Within 1 minute

Alert:

Critical

Explanation:

Many malware samples execute from temp directories and immediately attempt command-and-control communication.
