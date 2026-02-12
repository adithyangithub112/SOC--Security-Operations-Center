# 1. Phishing Incident

## Stage 1: Preparation

- Email security gateway configured
- MFA enabled for critical accounts
- User awareness training conducted
- Phishing response playbook available
- SIEM integrated with email logs

Documentation:

- Security controls inventory
- Email filtering configuration
- Training attendance records

---

## Stage 2: Identification

A user reports a suspicious email requesting credential verification.

SOC Actions:

- Analyze email headers
- Check embedded URLs in sandbox
- Verify sender reputation
- Search SIEM for similar emails

Documentation:

- Timestamp of report
- Sender address and IP
- Affected users
- Email subject and payload hash

---

## Stage 3: Containment

- Remove phishing email from all mailboxes
- Block malicious domain and sender
- Temporarily disable compromised account (if clicked)

Documentation:

- Blocked domain/IP details
- List of affected users
- Containment time recorded

---

## Stage 4: Eradication

- Reset compromised passwords
- Revoke active sessions
- Enable MFA if not enabled

Documentation:

- Account reset confirmation
- Security configuration changes
- IOC updates to SIEM

---

## Stage 5: Recovery

- Restore user access
- Monitor for suspicious login attempts
- Conduct additional monitoring for 7–14 days

Documentation:

- Recovery validation logs
- Monitoring report summary

---

## Stage 6: Lessons Learned

- Identify why email bypassed filters
- Update phishing detection rules
- Conduct refresher training

Documentation:

- Root cause analysis
- Updated detection improvements
- Final incident report

---

# 2. DDoS Attack

## Stage 1: Preparation

- DDoS mitigation service configured
- Traffic baselines documented
- ISP contact procedures defined

Documentation:

- Network architecture diagram
- Baseline traffic reports

---

## Stage 2: Identification

Unusual traffic spike causing service downtime.

SOC Actions:

- Analyze firewall logs
- Confirm abnormal traffic volume
- Identify source regions/IP ranges

Documentation:

- Time attack started
- Traffic volume statistics
- Targeted service

---

## Stage 3: Containment

- Enable DDoS mitigation service
- Block malicious IP ranges
- Rate-limit traffic

Documentation:

- Mitigation activation time
- Firewall rule updates

---

## Stage 4: Eradication

- Remove temporary firewall rules
- Patch exploited vulnerabilities (if applicable)

Documentation:

- Attack vector analysis
- Configuration changes made

---

## Stage 5: Recovery

- Restore normal traffic routing
- Confirm service stability

Documentation:

- Service uptime confirmation
- Performance monitoring logs

---

## Stage 6: Lessons Learned

- Improve traffic anomaly detection
- Update network capacity planning

Documentation:

- Post-incident review report
- Risk mitigation plan

---

# 3. Ransomware Attack

## Stage 1: Preparation

- Regular offline backups
- EDR deployed
- Incident response playbook available

Documentation:

- Backup verification logs
- EDR coverage list

---

## Stage 2: Identification

Multiple files encrypted and ransom note displayed.

SOC Actions:

- Identify infected host
- Analyze malware hash
- Check lateral movement activity

Documentation:

- Encryption timestamp
- Systems affected
- Ransomware variant identified

---

## Stage 3: Containment

- Immediately isolate infected endpoints
- Disable shared drives
- Block malicious command-and-control IPs

Documentation:

- Isolation time
- Network segmentation steps

---

## Stage 4: Eradication

- Remove malware
- Patch vulnerabilities exploited
- Reset credentials

Documentation:

- Malware removal confirmation
- Vulnerability remediation evidence

---

## Stage 5: Recovery

- Restore files from clean backups
- Reconnect systems to network
- Monitor closely for reinfection

Documentation:

- Backup restoration logs
- System integrity verification

---

## Stage 6: Lessons Learned

- Review EDR detection gaps
- Improve patch management
- Strengthen user awareness

Documentation:

- Root cause analysis
- Updated ransomware defense strategy

---

# 4. Data Breach

## Stage 1: Preparation

- Data classification policies
- Access control policies
- DLP solutions implemented

Documentation:

- Access control matrix
- Data inventory list

---

## Stage 2: Identification

Large abnormal outbound data transfer detected.

SOC Actions:

- Review DLP alerts
- Identify user account involved
- Determine data type exposed

Documentation:

- Data volume transferred
- Source and destination IP
- Sensitive data categories

---

## Stage 3: Containment

- Disable compromised account
- Block suspicious IP
- Restrict database access

Documentation:

- Account suspension record
- Network block confirmation

---

## Stage 4: Eradication

- Remove backdoors
- Patch exploited vulnerabilities
- Rotate credentials

Documentation:

- Security patch logs
- Credential reset documentation

---

## Stage 5: Recovery

- Restore system security posture
- Notify stakeholders (legal/compliance if required)

Documentation:

- Notification records
- Recovery validation

---

## Stage 6: Lessons Learned

- Improve monitoring rules
- Enhance access restrictions
- Conduct compliance review

Documentation:

- Breach impact assessment
- Updated data protection policy

---

# 5. Brute Force Attack

## Stage 1: Preparation

- Account lockout policies
- MFA implementation
- SIEM alerting for failed logins

Documentation:

- Authentication policy document
- MFA coverage report

---

## Stage 2: Identification

Multiple failed login attempts detected from a single IP.

SOC Actions:

- Review authentication logs
- Confirm attack pattern
- Identify targeted accounts

Documentation:

- Number of failed attempts
- Source IP and geolocation

---

## Stage 3: Containment

- Block attacking IP
- Lock affected accounts

Documentation:

- Firewall block entry
- Account lock confirmation

---

## Stage 4: Eradication

- Reset passwords
- Investigate if account was successfully accessed

Documentation:

- Password reset confirmation
- Account audit logs

---

## Stage 5: Recovery

- Unlock accounts
- Monitor login activity

Documentation:

- Recovery timestamp
- Ongoing monitoring report

---

## Stage 6: Lessons Learned

- Strengthen password policies
- Improve anomaly detection thresholds

Documentation:

- Updated authentication policy
- Incident closure report

---
