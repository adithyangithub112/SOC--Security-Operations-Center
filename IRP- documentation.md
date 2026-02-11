# Incident Response Plan (IRP) – Detailed Documentation

An Incident Response Plan (IRP) is a structured process followed by a Security Operations Center (SOC) to detect, respond to, contain, and recover from cybersecurity incidents while minimizing business impact.

---

A. The Six Stages of Incident Response

1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned

---

B. Short Explanation of Each Stage

1. Preparation

Definition:

Activities performed before an incident occurs to ensure the organization is ready to respond effectively.

Key Activities:

- Develop and document incident response policies and SOPs
- Define SOC roles (L1, L2, L3 analysts)
- Deploy and configure security tools (SIEM, EDR, IDS/IPS)
- Conduct training and tabletop exercises
- Maintain backups and patch management processes

SOC Example:

The SOC configures correlation rules in the SIEM to detect brute-force attempts and conducts phishing simulation training for employees.

---

1. Identification

Definition:

Detecting, analyzing, and confirming whether an event is a real security incident.

Key Activities:

- Monitor alerts from SIEM, EDR, IDS
- Review logs and network traffic
- Perform initial triage
- Classify incident severity
- Eliminate false positives

SOC Example:

An L1 analyst detects multiple failed login attempts followed by a successful login from a foreign IP. After log review, it is confirmed as a brute-force attack.

---

1. Containment

Definition:

Limiting the scope and impact of the incident to prevent further damage.

Types:

- Short-term containment (immediate isolation)
- Long-term containment (temporary fixes while investigation continues)

Key Activities:

- Isolate infected endpoints from the network
- Disable compromised accounts
- Block malicious IP addresses and domains
- Apply firewall or access control changes

SOC Example:

After detecting ransomware on a workstation, the SOC isolates the device from the network and blocks the command-and-control IP address at the firewall.

---

1. Eradication

Definition:

Removing the root cause of the incident and eliminating malicious artifacts from the environment.

Key Activities:

- Remove malware and malicious files
- Patch exploited vulnerabilities
- Delete unauthorized user accounts
- Clean registry changes or persistence mechanisms

SOC Example:

The L2 analyst identifies a malicious scheduled task created by malware and removes it. The vulnerable software is patched to prevent re-exploitation.

---

1. Recovery

Definition:

Restoring systems and operations to normal while ensuring the threat is fully removed.

Key Activities:

- Restore systems from clean backups
- Reconnect cleaned systems to the network
- Monitor for reinfection or suspicious activity
- Validate system integrity

SOC Example:

After ransomware removal, the IT team restores files from backup and reconnects the system to the network while the SOC closely monitors for abnormal behavior.

---

1. Lessons Learned

Definition:

Post-incident review to improve security posture and prevent similar incidents in the future.

Key Activities:

- Conduct post-incident meetings
- Document timeline and response actions
- Identify gaps in detection and response
- Update policies and detection rules
- Provide additional staff training

SOC Example:

After analyzing the ransomware attack, the SOC updates email filtering rules, enhances endpoint monitoring, and conducts additional phishing awareness training.
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/20f3436b-d6a6-4477-aaa6-135c2163be3b" />

