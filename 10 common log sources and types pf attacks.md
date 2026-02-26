# Common Log Sources Used to Detect Security Attacks

Below is a list of 10 commonly used log sources in Security Operations Centers (SOCs), along with the types of attacks each source helps detect.

---

## Log Sources and Their Security Value

| #  | Log Source | What It Logs | Types of Attacks Detected |
|----|------------|--------------|----------------------------|
| 1  | **Firewall Logs** | Allowed/blocked traffic, source/destination IPs, ports, protocols | Port scanning, brute-force attempts, unauthorized access attempts, command-and-control (C2) communication |
| 2  | **IDS/IPS Logs** | Intrusion alerts, signature matches, suspicious payloads | Exploitation attempts, SQL injection, cross-site scripting (XSS), malware traffic, network reconnaissance |
| 3  | **Active Directory (AD) Logs** | User logins, account lockouts, group changes, privilege assignments | Brute force attacks, password spraying, privilege escalation, unauthorized account creation |
| 4  | **Web Server Logs (Apache/Nginx/IIS)** | HTTP requests, URLs accessed, status codes, client IPs | Web attacks (SQL injection, XSS), directory traversal, web shell access, brute-force login attempts |
| 5  | **VPN Logs** | Remote login attempts, session duration, IP addresses, authentication results | Account compromise, impossible travel logins, brute force against VPN, unauthorized remote access |
| 6  | **Endpoint Logs (Windows/Linux)** | Process execution, login events, file access, system changes | Malware execution, lateral movement, suspicious PowerShell usage, log tampering |
| 7  | **EDR (Endpoint Detection & Response) Logs** | Behavioral alerts, suspicious processes, file modifications, memory activity | Ransomware activity, fileless malware, privilege escalation, advanced persistent threats (APT) |
| 8  | **DNS Logs** | Domain queries, response codes, queried domain names | DNS tunneling, malware beaconing, data exfiltration, communication with malicious domains |
| 9  | **Email Security Logs** | Email sender/receiver details, attachments, spam detections | Phishing attacks, malicious attachments, business email compromise (BEC), malware delivery |
| 10 | **Database Logs** | Query execution, failed logins, privilege changes, data exports | SQL injection, data exfiltration, unauthorized data access, insider threats |

---

# Summary of Detection Coverage

- **Network-based detection**: Firewall, IDS/IPS, DNS logs  
- **Identity-based detection**: Active Directory, VPN logs  
- **Application-based detection**: Web server, database logs  
- **Endpoint-based detection**: OS logs, EDR logs  
- **Email-based detection**: Email gateway/security logs  

A well-configured SOC integrates all these log sources into a SIEM to correlate activity across systems and detect complex multi-stage attacks.
