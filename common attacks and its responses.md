# 1. Malware Infection

## Summary

Malware refers to malicious software such as viruses, trojans, ransomware, spyware, or worms that infect systems to steal data, disrupt operations, or gain unauthorized access.

## Common Indicators

- Suspicious processes running
- Antivirus alerts
- Unexpected outbound traffic
- Encrypted files (ransomware)

## Response Actions

1. Isolate the infected endpoint from the network
2. Identify malware type using EDR/SIEM logs
3. Remove malware using security tools
4. Patch vulnerabilities exploited
5. Reset affected credentials
6. Monitor for reinfection

---

# 2. Phishing Attack

## Summary

A phishing attack involves fraudulent emails or messages designed to trick users into revealing credentials, financial data, or downloading malware.

## Common Indicators

- Suspicious sender address
- Fake login pages
- Urgent or threatening language
- Unusual attachments or links

## Response Actions

1. Block malicious sender/domain at email gateway
2. Remove phishing email from user mailboxes
3. Reset compromised user credentials
4. Enable MFA if not already active
5. Conduct user awareness communication
6. Monitor account for suspicious activity

---

# 3. Ransomware Attack

## Summary

Ransomware is a type of malware that encrypts files and demands payment for decryption.

## Common Indicators

- Files renamed or encrypted
- Ransom note displayed
- Sudden file access spikes
- Disabled backups

## Response Actions

1. Immediately isolate affected systems
2. Disable shared drives if spreading
3. Identify ransomware variant
4. Restore data from backups
5. Conduct forensic investigation
6. Notify management and legal if required

---

# 4. Brute Force Attack

## Summary

An attacker attempts multiple password combinations to gain unauthorized access to accounts or systems.

## Common Indicators

- Multiple failed login attempts
- Login attempts from unusual IPs
- Account lockouts

## Response Actions

1. Block attacking IP addresses
2. Enforce account lockout policies
3. Reset affected passwords
4. Enable MFA
5. Review logs for successful compromise

---

# 5. Insider Threat

## Summary

A security threat originating from within the organization, either malicious (intentional) or negligent (accidental).

## Common Indicators

- Unusual data downloads
- Access outside working hours
- Access to unauthorized systems

## Response Actions

1. Review user activity logs
2. Temporarily suspend account if necessary
3. Preserve evidence for investigation
4. Involve HR and management
5. Restrict excessive privileges

---

# 6. Data Breach

## Summary

Unauthorized access, exposure, or theft of sensitive information such as customer data or intellectual property.

## Common Indicators

- Large outbound data transfers
- Access to sensitive databases
- Alerts from DLP systems

## Response Actions

1. Identify affected data and systems
2. Contain access immediately
3. Assess impact and scope
4. Notify legal/compliance teams
5. Inform affected parties if required
6. Strengthen access controls

---

# 7. Denial of Service (DoS/DDoS)

## Summary

An attack that floods a system or network with traffic to disrupt availability.

## Common Indicators

- Sudden traffic spike
- Server performance degradation
- Service unavailability

## Response Actions

1. Activate DDoS protection services
2. Block malicious IP ranges
3. Rate-limit incoming traffic
4. Coordinate with ISP or cloud provider
5. Monitor service restoration

---

# 8. Unauthorized Access

## Summary

When an attacker gains access to systems, accounts, or data without permission.

## Common Indicators

- Login from unusual location
- Privilege escalation alerts
- New admin accounts created

## Response Actions

1. Immediately disable compromised account
2. Reset credentials
3. Review access logs
4. Remove unauthorized privileges
5. Conduct deeper compromise assessment

---

# 9. Web Application Attack (e.g., SQL Injection, XSS)

## Summary

Attacks targeting vulnerabilities in web applications to access or manipulate backend data.

## Common Indicators

- Unusual database queries
- Error messages in web logs
- Suspicious URL parameters

## Response Actions

1. Block malicious IPs
2. Patch vulnerable application
3. Validate input sanitization
4. Review database for changes
5. Conduct vulnerability scan

---

# 10. Privilege Escalation

## Summary

When a user or attacker gains higher-level access rights than originally assigned.

## Common Indicators

- Normal user accessing admin resources
- Unexpected changes in user roles
- New admin-level processes

## Response Actions

1. Revoke unauthorized privileges
2. Audit account activity
3. Reset credentials
4. Patch exploited vulnerabilities
5. Review access control policies

---

# Quick Comparison Table

| Incident Type | Main Risk | Immediate Priority |
| --- | --- | --- |
| Malware | System compromise | Isolate endpoint |
| Phishing | Credential theft | Reset passwords |
| Ransomware | Data encryption | Contain spread |
| Brute Force | Account takeover | Block IP & enforce MFA |
| Insider Threat | Data misuse | Audit & restrict access |
| Data Breach | Sensitive data exposure | Contain & notify |
| DDoS | Service disruption | Traffic mitigation |
| Unauthorized Access | System compromise | Disable account |
| Web Attack | Database compromise | Patch vulnerability |
| Privilege Escalation | Full system control | Remove elevated rights |
