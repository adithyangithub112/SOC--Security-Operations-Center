# Integrating Logs into a SIEM

---

## 1. Introduction to Log Integration in SIEM

A Security Information and Event Management (SIEM) system collects, analyzes, and correlates logs from multiple sources to detect security incidents, monitor compliance, and support investigations.

Log integration is the process of:

1. Collecting logs from various systems.
2. Transmitting them securely to the SIEM.
3. Parsing and normalizing the data.
4. Storing and correlating events for analysis.

---

# A) Types of Log Sources

Understanding log sources is the first step in integration.

## 1. Network Devices

### a) Firewalls

- Log allowed and blocked traffic.
- Record source IP, destination IP, ports, protocol, action (allow/deny).
- Detect intrusion attempts and policy violations.
- Example logs:
    - Denied inbound connection
    - Port scanning activity
    - VPN login attempts

### b) Routers and Switches

- Interface status changes.
- Configuration changes.
- Routing updates.
- Unauthorized access attempts.

### c) IDS/IPS Systems

- Intrusion alerts.
- Signature matches.
- Suspicious network behavior.

---

## 2. Endpoints

### a) Windows Endpoints

- Security Event Logs:
    - Logon/logoff events
    - Failed login attempts
    - Account lockouts
    - Privilege escalation
- System Logs:
    - Service start/stop
    - Driver errors
- Application Logs

### b) Linux Endpoints

- Authentication logs (/var/log/auth.log)
- Syslog (/var/log/syslog)
- SSH login attempts
- Sudo usage

### c) EDR Solutions

- Malware detections
- Suspicious process execution
- File modifications
- Behavioral alerts

---

## 3. Servers

### a) Application Servers

- Web server logs (Apache, Nginx)
- API request logs
- Error logs

### b) Database Servers

- Failed login attempts
- Query execution logs
- Privilege changes

### c) Email Servers

- Spam detection logs
- Attachment scanning results
- Mail flow records

---

# B) Log Integration Methods

There are multiple methods to integrate logs into a SIEM.

---

## 1. Syslog-Based Integration

### Description:

Syslog is a standard protocol used to send log messages over a network.

### How it works:

1. Device generates log.
2. Log is sent via UDP/TCP (usually port 514).
3. SIEM receives and stores the log.

### Characteristics:

- Common in Linux and network devices.
- Lightweight and simple.
- Can be encrypted (Syslog over TLS).

### Advantages:

- Easy to configure.
- Widely supported.
- Real-time log forwarding.

### Limitations:

- UDP can lose packets.
- Limited structure in raw format.

---

## 2. Agent-Based Integration

### Description:

An agent is a lightweight software installed on endpoints or servers.

### How it works:

1. Agent monitors local log files.
2. Collects relevant logs.
3. Filters and compresses data.
4. Securely sends logs to SIEM.

### Examples:

- Splunk Universal Forwarder
- Wazuh Agent
- Winlogbeat

### Advantages:

- Reliable delivery.
- Encryption supported.
- Can preprocess logs.
- Works behind NAT/firewalls.

### Limitations:

- Requires installation and maintenance.
- Resource usage on endpoint.

---

## 3. API-Based Integration

### Description:

Logs are pulled or pushed via REST APIs.

### How it works:

1. SIEM authenticates to application using API key/token.
2. SIEM fetches logs periodically.
3. Logs are ingested and processed.

### Common for:

- Cloud platforms (AWS, Azure, GCP)
- SaaS applications (Office 365, Google Workspace)
- Security tools (EDR, Firewalls, CASB)

### Advantages:

- Ideal for cloud environments.
- Structured JSON data.
- Secure authentication.

### Limitations:

- Rate limits.
- Dependency on API availability.

---

# C) Log Parsing and Normalization

Raw logs are often unstructured and inconsistent. Before analysis, they must be parsed and normalized.

---

## 1. Parsing

Parsing extracts meaningful fields from raw log messages.

### Example (Raw Log):

Failed login from 192.168.1.10 for user admin at 10:30

### After Parsing:

- Event Type: Failed Login
- Source IP: 192.168.1.10
- Username: admin
- Timestamp: 10:30

### Methods:

1. Regular expressions
2. Prebuilt parsers (vendor-specific)
3. Log processing pipelines

---

## 2. Field Extraction

Common fields extracted:

- Timestamp
- Source IP
- Destination IP
- Username
- Hostname
- Event ID
- Severity
- Action (allow/deny)

---

## 3. Normalization

Normalization converts different log formats into a standard schema.

### Why normalization is needed:

Different systems represent the same event differently.

Example:

- Firewall: src_ip
- Windows: SourceNetworkAddress
- Linux: rhost

After normalization:

All mapped to:

- source_ip

### Common Normalization Standards:

1. Common Event Format (CEF)
2. Log Event Extended Format (LEEF)
3. Elastic Common Schema (ECS)

---

## 4. Enrichment (Optional but Important)

After normalization, logs can be enriched with:

- GeoIP lookup
- Threat intelligence (known malicious IP)
- Asset information (server role)
- User identity mapping

---

# D) Step-by-Step Log Integration Workflow

Below is the complete workflow of log integration into a SIEM.

---

## Step 1: Identify Log Sources

1. List all devices and systems:
    - Firewalls
    - Servers
    - Endpoints
    - Cloud services
2. Identify critical logs:
    - Authentication logs
    - Network traffic logs
    - Application logs
3. Prioritize based on risk.

---

## Step 2: Choose Integration Method

1. For network devices → Syslog
2. For endpoints → Agent-based
3. For cloud/SaaS → API-based
4. Ensure secure transmission (TLS, certificates).

---

## Step 3: Configure Log Forwarding

1. Enable logging on the source.
2. Set destination IP (SIEM server).
3. Configure protocol and port.
4. Test connectivity.
5. Verify logs are being received.

---

## Step 4: Log Collection at SIEM

1. SIEM listener receives logs.
2. Logs are temporarily buffered.
3. Initial validation is performed.

---

## Step 5: Parsing

1. SIEM applies parsing rules.
2. Extracts structured fields.
3. Discards irrelevant data (if configured).

---

## Step 6: Normalization

1. Map fields to standard schema.
2. Convert timestamps to common timezone.
3. Standardize event categories.

---

## Step 7: Enrichment

1. Add asset context.
2. Add threat intelligence matches.
3. Add user or group information.

---

## Step 8: Storage and Indexing

1. Store logs in database or index.
2. Apply retention policy.
3. Ensure high availability and backup.

---

## Step 9: Correlation and Alerting

1. Create detection rules:
    - Multiple failed logins
    - Login from new country
    - Privilege escalation
2. Correlate events across sources.
3. Generate alerts.

---

## Step 10: Monitoring and Validation

1. Check ingestion health dashboard.
2. Monitor EPS (Events Per Second).
3. Validate that critical logs are not missing.
4. Tune parsing and correlation rules.

---
