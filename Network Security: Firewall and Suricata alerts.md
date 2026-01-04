## Overview of this Use Case
Integrated pfSense firewall and Suricata IDS logs with Wazuh to enable network threat detection. Since pfSense runs on FreeBSD and doesn't support the Wazuh agent, logs are forwarded via syslog. Built custom decoders to parse pfSense's raw logs, extracting fields like source IP, destination IP, action and protocol.

Suricata logs are forwarded using syslog-ng, which preserves the full EVE JSON format. Wazuh's built-in Suricata decoder handles these logs natively, providing immediate detection of network intrusions, web attacks, and malicious traffic patterns without custom rule development.

**Architecture:**
```
pfSense Firewall → Syslog → Custom Decoder → Wazuh
Suricata IDS → Syslog-ng → Native JSON Decoder → Wazuh
```
### PfSense Custom Decoder
PfSense's filterlog uses a comma-delimited format that Wazuh doesn't parse by default. I built a two-stage decoder, the parent identifies logs containing "filterlog," and the child uses regex to extract security-relevant fields from the comma-separated values.
```xml
<!-- Stage 1: Identify pfSense logs -->
<decoder name="pfsense-custom">
    <prematch>filterlog</prematch>
</decoder>
<!-- Stage 2: Extract fields using regex -->
<decoder name="pfsense-fields">
    <parent>pfsense-custom</parent>
    <regex>^(\w+)[\d+]: \S*,\S*,\S*,(\S*),\S*,\S*,(\S*),\S*,\S*,\S*,\S*,\S*,\S*,\S*,\S*,\S*,(\S*),\S*,(\S*),(\S*),(\d*),(\d*),\S*</regex>
    <order>logsource,id,action,protocol,srcip,dstip,srcport,dstport</order>
</decoder>
```
#### Fields extracted
| Field | Description | Example Value |
|-------|-------------|---------------|
| `logsource` | Log program name | filterlog |
| `id` | Firewall rule ID | 1000000103 |
| `action` | Firewall decision | block, pass |
| `protocol` | Network protocol | TCP, UDP, ICMP |
| `srcip` | Source IP address | 192.168.1.20 |
| `dstip` | Destination IP address | 192.168.1.1 |
| `srcport` | Source port number | 26760 |
| `dstport` | Destination port number | 443 

### PfSense Custom Rules

```xml
<!-- Base rule: Matches all pfSense firewall logs -->
<group name="pfsense, custom,">
  <rule id="100900" level="0">
    <decoded_as>pfsense-custom</decoded_as>
    <field name="logsource">filterlog</field>
    <description>pfSense firewall rules grouped.</description>
  </rule>

  <!-- Detect allowed connections -->
  <rule id="100901" level="4">
    <if_sid>100900</if_sid>
    <action>pass</action>
    <options>no_full_log</options>
    <description>pfSense firewall allow event.</description>
    <group>firewall_allow,pci_dss_1.4,gpg13_4.12,hipaa_164.312.a.1,nist_800_53_SC.7,tsc_CC6.7,tsc_CC6.8,</group>
  </rule>    
 
  <!-- Detect blocked connections -->
  <rule id="100902" level="5">
    <if_sid>100900</if_sid>
    <action>block</action>
    <options>no_full_log</options>
    <description>pfSense firewall drop event.</description>
    <group>firewall_block,pci_dss_1.4,gpg13_4.12,hipaa_164.312.a.1,nist_800_53_SC.7,tsc_CC6.7,tsc_CC6.8,</group>
  </rule>

  <!-- Correlation rule: Detect port scanning or brute force (20+ blocks from same IP in 45 seconds) -->
  <rule id="100903" level="10" frequency="20" timeframe="45" ignore="240">
    <if_matched_sid>100902</if_matched_sid>
    <same_source_ip />
    <description>Multiple pfSense firewall blocks events from same source.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>multiple_blocks,pci_dss_1.4,pci_dss_10.6.1,gpg13_4.12,hipaa_164.312.a.1,hipaa_164.312.b,nist_800_53_SC.7,nist_800_53_AU.6,tsc_CC6.7,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
</group>
```
#### Created a hierarchical rule structure to detect firewall activity and identify suspicious patterns:
- Rule 100900 - Base rule that groups all pfSense firewall logs for further analysis.
- Rule 100901 - Logs allowed connections for baseline visibility.
- Rule 100902 - Alerts on blocked connections indicating denied access attempts.
- Rule 100903 - Correlation rule that detects port scanning or brute force activity when the same source IP triggers 20+ firewall blocks within 45 seconds. Maps to MITRE ATT&CK T1110.

#### Example of logs 

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Firewall%20Logs.jpg" width="5000">
  <br>
  <strong>Example of automated scans that hit the pfSense firewall</strong>
</p>

## Suricata Integration

Deployed Suricata IDS on pfSense to monitor network traffic for intrusions and exploit attempts. Configured syslog-ng to read Suricata's EVE JSON output and forward alerts to Wazuh in real-time.

**Configuration:**
- **Suricata:** Installed via pfSense package manager, monitoring LAN interface
- **Log Format:** EVE JSON (`/var/log/suricata/suricata_em1/eve.json`)
- **Forwarding:** syslog-ng sends JSON alerts to Wazuh (UDP 514)
- **Detection:** Wazuh's native Suricata decoder parses alerts automatically

No custom decoders or rules required—Wazuh provides built-in support for Suricata's JSON format.
