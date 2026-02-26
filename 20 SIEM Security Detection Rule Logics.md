# 20 SIEM Security Detection Rule Logics

| # | Rule Name | Log Source | Detection Condition | Alert Criteria | Purpose |
|---|------------|------------|--------------------|----------------|----------|
| 1 | Brute Force Login | AD / Windows Security Logs | ≥15 failed logins from same IP within 10 minutes | High alert | Detect password guessing attacks |
| 2 | Password Spraying | AD Logs | ≥20 failed logins across ≥10 accounts from one IP within 15 minutes | Medium/High alert | Detect single-password attacks across many users |
| 3 | Successful Login After Failures | AD Logs | ≥5 failed logins followed by 1 success from same IP within 5 minutes | High alert | Detect possible credential compromise |
| 4 | Account Lockout Spike | AD Logs | ≥5 account lockouts within 10 minutes | Medium alert | Detect brute force attempts affecting multiple users |
| 5 | Privileged Group Addition | AD Logs | User added to Domain Admins group | Critical alert | Detect privilege escalation |
| 6 | Suspicious PowerShell Execution | Endpoint Logs (Event ID 4688) | PowerShell executed with "-EncodedCommand" | High alert | Detect fileless malware or malicious scripts |
| 7 | Ransomware File Activity | EDR / File Logs | ≥100 file modifications within 5 minutes | Critical alert | Detect mass encryption behavior |
| 8 | Internal Port Scan | Firewall Logs | Single IP connects to ≥20 ports within 2 minutes | High alert | Detect reconnaissance activity |
| 9 | Lateral Movement via RDP | Windows Logs / Firewall | One host connects to ≥10 internal systems via RDP in 5 minutes | High alert | Detect internal spread after compromise |
| 10 | VPN Brute Force | VPN Logs | ≥10 failed VPN logins from same IP within 10 minutes | High alert | Detect external remote access attack |
| 11 | Impossible Travel | Cloud Auth Logs | Login from two distant countries within 2 hours | High alert | Detect account takeover |
| 12 | Phishing Email Delivery | Email Gateway Logs | Email with malicious attachment delivered | Medium/High alert | Detect phishing attempts |
| 13 | Malware Hash Detected | EDR Logs | File hash matches threat intelligence feed | Critical alert | Detect known malware execution |
| 14 | DNS Tunneling Activity | DNS Logs | ≥1000 DNS queries from single host within 10 minutes | High alert | Detect possible data exfiltration |
| 15 | Command & Control Communication | Firewall / Proxy Logs | Outbound traffic to known malicious IP/domain | High alert | Detect infected host beaconing |
| 16 | Log Tampering | Windows Logs (Event ID 1102) | Security logs cleared | Critical alert | Detect attacker covering tracks |
| 17 | Suspicious Service Creation | Windows Logs (Event ID 7045) | New service installed outside change window | High alert | Detect persistence mechanisms |
| 18 | Data Exfiltration Spike | Firewall Logs | Outbound data transfer exceeds baseline by 5x | High alert | Detect large data theft |
| 19 | Web Application SQL Injection | Web Server Logs | URL contains SQL keywords (UNION SELECT, OR 1=1) | High alert | Detect SQL injection attacks |
| 20 | Multiple MFA Failures | Cloud Auth Logs | ≥5 MFA failures for same user within 10 minutes | Medium/High alert | Detect MFA fatigue or account abuse |
