# 1. Introduction to Sigma Rules

Sigma is an open-standard rule format used to describe detection logic for security events in a structured, platform-independent way. It allows security teams to write a detection rule once and convert it into queries for multiple SIEM platforms such as Splunk, Elastic, Microsoft Sentinel, QRadar, and others.

Sigma helps SOC teams:

- Share detection logic easily
- Maintain consistent rule standards
- Reduce vendor lock-in
- Deploy detections across different SIEMs

It is often compared to YARA, but while YARA focuses on malware pattern matching, Sigma focuses on log-based detection in SIEM systems.

---

# A) Structure and Logic of Sigma Rules

Sigma rules are written in YAML format and contain structured sections that define detection behavior.

---

## Basic Structure of a Sigma Rule

```
title: Rule Title
id: unique-rule-id
status: stable
description: Description of what the rule detects
author: Analyst Name
date: YYYY/MM/DD
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    FieldName: Value
  condition: selection
falsepositives:
  - Description of expected false positives
level: high
```

---

## 1. Metadata Section

This section documents rule details:

- title: Name of the rule
- id: Unique identifier
- description: What the rule detects
- author: Creator
- date: Creation date
- status: experimental, test, stable

Metadata helps SOC teams manage rule lifecycle and documentation.

---

## 2. Logsource Section

Defines where the rule applies.

Example:

```
logsource:
  product: windows
  category: process_creation
```

This tells the SIEM:

- Product: Windows
- Log type: Process creation logs

Logsource ensures the rule targets the correct data source.

---

## 3. Detection Section

This is the core logic of the rule.

Example:

```
detection:
  selection:
    Image: powershell.exe
    CommandLine|contains:"-EncodedCommand"
  condition: selection
```

The detection section includes:

- selection: Matching criteria
- condition: Logical expression combining selections

Logical operators supported include:

- and
- or
- not
- 1 of selection*
- all of them

This makes Sigma flexible for complex detections.

---

## 4. False Positives Section

Documents known legitimate scenarios that may trigger the rule.

Example:

```
falsepositives:
  - Administrative scripts
```

This helps SOC teams during tuning.

---

## 5. Level Section

Defines severity:

- low
- medium
- high
- critical

This assists in prioritizing alerts.

---

# B) Sigma as a Universal Detection Format

Different SIEM platforms use different query languages:

- Splunk uses SPL
- Microsoft Sentinel uses KQL
- Elastic uses KQL/Lucene
- QRadar uses AQL

Without Sigma, detection rules must be rewritten for each platform.

Sigma acts as:

- A universal detection description format
- A translation layer between analysts and SIEM platforms
- A standardized detection-sharing mechanism

This allows:

1. Community rule sharing
2. Easier collaboration between organizations
3. Faster deployment of new threat detections
4. Reduced dependency on vendor-specific syntax

In essence, Sigma separates detection logic from SIEM implementation.

---

# C) Sample Sigma Rule with Explanation

Below is a sample Sigma rule that detects multiple failed login attempts (possible brute force attack).

```
title: Multiple Failed Windows Logins
id: 8a3b2c4d-1111-2222-3333-abcdef123456
status: experimental
description: Detects multiple failed login attempts from the same IP within a short period
author: SOC Analyst
date: 2026/02/26
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 5m
  condition: selection | count(SourceIpAddress) by SourceIpAddress > 10
falsepositives:
  - User mistyping password
  - Password expiration events
level: high
```

---

## Explanation of the Rule

### Rule Objective

Detect possible brute force attacks against Windows systems.

---

### Log Source

- Product: Windows
- Service: Security log

Event ID 4625 represents failed login attempts.

---

### Detection Logic

1. Select Event ID 4625 (failed login).
2. Group by Source IP address.
3. Count number of events within 5 minutes.
4. Trigger alert if count exceeds 10.

This pattern indicates automated password guessing attempts.

---

### False Positives

- Users repeatedly entering incorrect passwords
- Locked accounts after password change

These must be considered during tuning.

---

### Severity

High, because repeated failed logins may indicate an attack in progress.

---

# D) Converting Sigma Rules for Different SIEMs

Sigma rules are converted using tools such as:

- sigmac (Sigma converter tool)
- pySigma framework

---

## Conversion Process

1. Analyst writes rule in Sigma YAML format.
2. Conversion tool translates it into SIEM-specific query language.
3. Output query is deployed into the SIEM.

---

## Example Conversions

### Splunk (SPL)

Converted query may look like:

```
index=wineventlog EventCode=4625
| stats count by SourceIpAddress
| where count > 10
```

---

### Microsoft Sentinel (KQL)

Converted query may look like:

```
SecurityEvent
| where EventID == 4625
| summarize count() by SourceIpAddress
| where count_ > 10
```

---

### Elastic (KQL)

```
event.code:4625
```

With additional aggregation in Elastic SIEM interface.

---

## Benefits of Conversion

- Write once, deploy anywhere
- Standardize detection engineering
- Share rules between organizations
- Reduce development time
