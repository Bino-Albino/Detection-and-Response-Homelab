## Overview of this Use Case
Integrated Microsoft 365 audit logs with Wazuh to extend detection capabilities into cloud environments. When the Office365 module ingests authentication, file access, and administrative activity, custom correlation rules analyze patterns for suspicious behavior. Anomalies such as brute force attempts, mass file downloads, and bulk deletions trigger high-severity alerts indicating potential account compromise or data exfiltration.



**Key Components:**
- **Office 365 Management API**: Audit log source
- **Wazuh Office365**: Module: Log ingestion and parsing
- **Custom Rules**: Pattern detection for suspicious activity
- **Alerting**: Wazuh dashboard + Discord webhook

## Implementation

### Step 1: Register Application in Azure AD

- To authenticate with the Microsoft identity platform endpoint, you need to register an app in your Azure portal.

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Azure-App.png" width="2000">
  <br>
</p>

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Azure-App2.jpg" width="2000">
  <br>
  <strong>App Registration</strong>
</p>

### Step 2: Enable Microsoft365 Audit Logging in the Purview App

- Navigate to https://purview.microsoft.com/
- Left-hand menu, Solutions > Audit
- If blue "Start Recording User and Admin Banner" is present, click to enable.


<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Audit%20Logging%20Activation.png" width="2000">
  <br>
</p>

### Step 3: Configure Wazuh Office365 Module

On the Wazuh Manager, edit ```/var/ossec/etc/ossec.conf```:

```xml
<office365>
    <enabled>yes</enabled>
    <interval>1m</interval>
    <curl_max_size>1M</curl_max_size>
    <only_future_events>no</only_future_events>
    <api_auth>
      <tenant_id>YOUR-TENANT-ID</tenant_id>
      <client_id>YOUR-CLIENT-ID</client_id>
      <client_secret>YOUR-CLIENT-SECRET</client_secret>
      <api_type>commercial</api_type>
    </api_auth>
    <subscriptions>
      <subscription>Audit.SharePoint</subscription>
      <subscription>Audit.AzureActiveDirectory</subscription>
      <subscription>Audit.Exchange</subscription>
      <subscription>Audit.General</subscription>
      <subscription>DLP.All</subscription>
    </subscriptions>
  </office365>
```
## Baseline Visibility

At this point, Microsoft 365 audit logs are flowing into Wazuh via the Management API. The Office365 module automatically parses and normalizes the data, extracting fields like user identity, operation type, source IP, and timestamps. This provides baseline visibility into cloud activity before custom detection rules are applied.

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Microsoft365%20Baseline%20View.jpg" width="2000">
  <br>
  <strong>Dashboard Overview</strong>
</p>

### Step 4: Create Custom Detection Rules

### Use Case 1: Mass File Deletion

**Threat Scenario:** An attacker or malicious insider deletes large numbers of files to destroy evidence or cause disruption.

**Detection Logic:** Triggers when the same user deletes 50+ files within 10 minutes. Correlates multiple file deletion events (Rule 91537) from the same `UserId`.

**Rule Configuration:**

```xml
 <rule id="100002" level="10" frequency="50" timeframe="600">
    <if_matched_sid>91537</if_matched_sid>
    <same_field>office365.UserId</same_field>
    <field name="office365.Operation" type="osregex">^FileRecycled$</field>
    <description>Office 365: Mass delete Detected from $(office365.UserId)</description>
  </rule>
```
**Alert Example:**
<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Mass%20Delete%20Use%20Case.jpg?raw=true" width="2000">
  <br>
</p>

### Use Case 2: Mass File Download (Data Exfiltration)

**Threat Scenario:** Bulk file downloads indicating potential data theft or exfiltration.

**Detection Logic:** - Triggers when a single user downloads 50+ files within 10 minutes and correlates `FileDownloaded` operations from the same `UserId`

**Rule Configuration:**

```xml
<rule id="100004" level="10" frequency="50" timeframe="600">
    <if_matched_sid>91702</if_matched_sid>
    <same_field>office365.UserId</same_field>
    <field name="office365.Operation" type="osregex">^FileDownloaded$</field>
    <description>Office 365: Possible Data Exfiltration by user $(office365.UserId)</description>
  </rule>
```
**Alert Example:**
<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Data%20Exfil.jpg?raw=true" width="2000">
  <br>
</p>

### Use Case 3: Potential Brute Force Attempt

**Threat Scenario:** Multiple failed login attempts indicating credential stuffing or password spraying.

**Detection Logic:** - Triggers on 5+ failed logins from the same user within 5 minutes and correlates failed authentication events from the same `UserId`

**Rule Configuration:**

```xml
  <rule id="100003" level="10" frequency="5" timeframe="300">
    <if_matched_sid>91545</if_matched_sid>
    <same_field>office365.UserId</same_field>
    <field name="office365.Operation" type="osregex">^UserLoginFailed$</field>
    <description>Office 365: Multiple Failed Logins from $(office365.UserId)</description>
  </rule>
```
**Alert Example:**
<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Brute%20Force.jpg" width="2000">
  <br>
</p>



