# Detection-and-Response-Homelab

#### About this Project
- A self-built blue-team lab focused on detection engineering, log analysis and active response using Wazuh and supporting tools.

- This project demonstrates the integration of various systems (cloud, endpoint, network) into a centralized SIEM, developing of custom rules to detect targeted attacks, and automating containment actions.

#### Technical Architecture & Stack

The lab is hosted on VirtualBox and is designed to mimic a small corporate network, providing a realistic environment for attack simulation and alert investigation.

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Home-Lab-Diagram.jpg" width="700">
  <br>
  <strong>HomeLab Diagram</strong>
</p>

#### Tech Stack

| Component | Tech Used | What it Does |
|----------|----------|--------------|
| SIEM | Wazuh | Centralized logging, correlation, and rule engine. |
| Network Security | pfSense + Suricata | Firewall and routing infrastructure with integrated IDS traffic analysis. |
| Endpoint | Sysmon + Wazuh Agents | Endpoint telemetry collection, including process creation, DNS activity and authentication events. |
| Cloud | Microsoft 365 | Ingestion of Microsoft 365 audit logs available from the tenant for visibility and experimentation. |
| Response | Active Response (Python) | Scripts that automatically ban IPs or remediate suspicious activity. |
| Alerting | Discord Webhooks | Real-time alert notifications delivered via webhook integration. |


## Key Implementations

Below are some of the more interesting detection and response use cases implemented in this lab.
Each item links to a detailed breakdown explaining the logic, rules and results.

🔹 [Active Response: VirusTotal Integration](./active.response.md) 

- **The Goal**: Automatically detect and delete malicious files downloaded on endpoints.

- **How**: Integrated the VirusTotal API with Wazuh. When the FIM (File Integrity Monitoring) module detects a new file, the hash is sent to VT. If the positive hit rate exceeds the threshold, an Active Response script immediately deletes the file and send an alert.


🔹 [Blocking SSH Anomalies (Geo/IP Filtering)](./active.response.md) 

- **The Goal**: protect the "Admin" account from logging in outside the corporate network.

- **How**: Created a custom rule to identify logins from outside the approved IP range. If the "Admin" user attempts a login from a non-whitelisted IP, the firewall immediately bans the source IP and block the user.


🔹 [Cloud Identity Monitoring (Microsoft 365)](./active.response.md) 

- **The Goal**: Gain visibility into SaaS environment threats.

- **How**: Configured the Wazuh Office365 module to ingest audit logs from Microsoft365. Created custom correlation rules to flag Brute Force attempts, suspicious file exfiltration attempts, and mass delete events.
