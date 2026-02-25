# 1. Threat Intelligence Feeds

## 1.1 What Are Threat Intelligence Feeds?

Threat intelligence feeds are structured data sources that provide information about known and emerging cyber threats.

They typically include:

○ Malicious IP addresses

○ Malicious domains

○ File hashes (MD5, SHA256)

○ URLs linked to phishing or malware

○ Command-and-Control (C2) server indicators

○ Threat actor tactics and techniques

These data points are called Indicators of Compromise (IOCs).

---

## 1.2 Purpose of Threat Intelligence Feeds

The main objective is to help SOC teams:

□ Detect known threats quickly

□ Enrich security alerts

□ Improve investigation accuracy

□ Proactively block malicious activity

□ Understand attacker behavior patterns

Threat feeds transform reactive security into proactive defense.

---

## 1.3 Popular Threat Intelligence Feed Sources

Below are widely used sources in SOC environments:

### Commercial Threat Intelligence Platforms

□ Recorded Future

□ CrowdStrike

□ Mandiant

□ IBM (X-Force Exchange)

Contribution to SOC:

○ High-quality curated intelligence

○ Attribution to threat actors

○ Advanced risk scoring

○ Context-rich investigation support

---

### Open-Source Threat Feeds

□ AlienVault OTX

□ Abuse.ch

□ Spamhaus Project

□ CISA

Contribution to SOC:

○ Free IOC lists

○ Community-shared threat data

○ Malware and phishing indicators

○ Public advisories and alerts

---

## 1.4 How Threat Feeds Are Used in SOC

Typical workflow:

1. Threat feed provides malicious IP list
2. SIEM ingests the feed
3. SOC rule checks logs against IOCs
4. If match found → Alert generated
5. Analyst investigates incident

Example:

If a firewall log shows outbound traffic to a known malicious IP from Abuse.ch, the SIEM flags it as high severity.

---

# 2. Syslog Servers

## 2.1 What Is a Syslog Server?

A syslog server is a centralized log collection system that receives, stores, and manages logs from multiple devices.

It uses the Syslog protocol (commonly UDP/TCP 514).

Devices that send logs include:

□ Firewalls

□ Routers

□ Switches

□ Linux servers

□ IDS/IPS systems

□ Applications

---

## 2.2 Purpose of a Syslog Server in SOC

The main goals are:

○ Centralized log collection

○ Log normalization

○ Log retention and storage

○ Easier monitoring and correlation

○ Evidence preservation for forensics

Without syslog, logs remain scattered across devices.

---

## 2.3 Role of Syslog in SOC Architecture

Typical flow:

1. Network devices generate logs
2. Logs are forwarded to syslog server
3. Syslog forwards logs to SIEM
4. SIEM correlates events
5. SOC monitors alerts

Example:

Firewall detects blocked connection

→ Sends log to syslog

→ SIEM correlates with threat feed

→ SOC receives alert

---

# 3. How Threat Intelligence Feeds and Syslog Work Together

## 3.1 Enhanced Threat Detection

Threat feeds provide malicious indicators.

Syslog provides real activity logs.

When combined:

□ Syslog shows outbound traffic to IP 185.x.x.x

□ Threat feed marks that IP as malware C2

□ SIEM correlates both

□ High-priority alert generated

This increases detection accuracy.

---

## 3.2 Incident Response Enhancement

Threat feeds help:

○ Identify severity of incident

○ Determine attacker attribution

○ Understand attack techniques

Syslog helps:

○ Trace full activity timeline

○ Identify affected systems

○ Collect forensic evidence

Together they enable:

□ Faster detection

□ Faster containment

□ Better root cause analysis

---
