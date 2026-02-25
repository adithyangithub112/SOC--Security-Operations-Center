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
