# Detection-and-Response-Homelab

#### About this Project
- A self-built blue-team lab focused on detection engineering, log analysis and active response using Wazuh and supporting tools.

- This project demonstrates the integration of various systems (cloud, endpoint, network) into a centralized SIEM, developing of custom rules to detect targeted attacks, and automating containment actions.

#### Technical Architecture & Stack

The lab is hosted on VirtualBox and is designed to mimic a small corporate network, providing a realistic environment for attack simulation and alert investigation.

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/HomeLab-Diagram.jpg" width="900">
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
| Attacker | Kali | Attack emulation VM. |
| Response | Active Response (Python) | Scripts that automatically ban IPs or remediate suspicious activity. |
| Alerting | Discord Webhooks | Real-time alert notifications delivered via webhook integration. |


## Key Implementations

Below are some of the more interesting detection and response use cases implemented in this lab.
Each item links to a detailed breakdown explaining the logic, rules and results.

### [Active Response: VirusTotal Integration](https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Active%20Response%3A%20VirusTotal%20Integration.md)
Integrated **VirusTotal** with **Wazuh** to enable automated malware detection and removal on endpoints. When FIM detects a new file in monitored directories, the hash is queried against VirusTotal's threat intelligence database. Malicious files trigger an Active Response script that deletes the file and generates an alert.

---

### [Blocking SSH Anomalies (GeoFencing)](https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Blocking%20SSH%20Anomalies%20(GeoFencing).md) 
Implemented geolocation-based access control for privileged accounts. Created a custom Wazuh rule to detect "Admin" logins originating from non-corporate IP ranges. Unauthorized login attempts trigger an Active Response that blocks the source IP via firewall rules and disables the compromised account.

---

### [Cloud Identity Monitoring (Microsoft 365)](https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Cloud%20Identity%20Monitoring%20(Microsoft%20365).md) 
Configured Wazuh to ingest Office 365 audit logs for cloud security monitoring. Created custom detection rules for brute force authentication attempts, suspicious file sharing activity, and mass deletion events. This extended SOC visibility beyond on-premises infrastructure into the organization's SaaS environment.

---

### [Network Security: Firewall and Suricata alerts](https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Network%20Security%3A%20Firewall%20and%20Suricata%20alerts.md) 
Integrated pfSense firewall and Suricata IDS logs with Wazuh for network-level threat detection. Built custom decoders to parse firewall events and IDS signatures.

