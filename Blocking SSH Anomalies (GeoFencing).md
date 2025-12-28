## Overview of this Use Case
Implemented geolocation-based access control to protect privileged accounts from unauthorized access. When the "test" admin account successfully authenticates via SSH from outside the corporate network range, Wazuh triggers an Active Response that immediately blocks the source IP and disables the compromised account.

## Architecture
```
SSH Login Attempt (from 203.0.113.45)
        ↓
Successful Authentication (Rule 5715)
        ↓
IP Geofence Check (Custom Rule 100005)
        ↓
Outside Corporate Range? (NOT 192.168.1.0/24)
        ↓
Active Response Triggered
        ↓
  1. Block Source IP (firewall-drop)
  2. Disable User Account (disable-account)
```

**Key Components:**
- **Parent Rule 5715:** Wazuh built-in rule for successful SSH authentication
- **Custom Geofence Rule:** Validates source IP against corporate range
- **Active Response:** Native Wazuh scripts for IP blocking and account lockout
- **Alerting:** Wazuh dashboard + Discord webhook


## Threat Scenario

**Attack:** An attacker steals admin credentials through phishing or credential dumping and attempts to access the server remotely.

**Detection:** Even with valid credentials, the login originates from outside the approved IP range (corporate network: 192.168.1.0/24), triggering automated defensive actions.

**Response:** The system immediately blocks the attacker's IP and disables the compromised account, preventing lateral movement.

## Implementation

### Step 1: Create Geofence Detection Rule

Add the following rule to `/var/ossec/etc/rules/local_rules.xml`
```xml
<group name="local,syslog,sshd,">
  <rule id="100005" level="5">
    <if_sid>5715</if_sid>
    <srcip negate="yes">192.168.1.0/24</srcip> 
    <user>test</user>
    <description>Successful SSH login by Admin from OUTSIDE the office</description>
  </rule>
</group>
```
**How it works:**
- **`if_sid 5715`**: Inherits from successful SSH login rule
- **`srcip negate="yes"`**: Matches IPs NOT in 192.168.1.0/24 range
- **`user test`**: Only monitors privileged "test" account

### Step 2: Configure Active Response

Add the following to `/var/ossec/etc/ossec.conf`

```xml
<active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100005</rules_id>
</active-response>

<active-response>
    <disabled>no</disabled>
    <command>disable-account</command>
    <location>local</location>
    <rules_id>100005</rules_id>
</active-response>
```

**Active Response Actions:**
1. **`firewall-drop`**: Adds iptables rule blocking the source IP for 10 minutes
2. **`disable-account`**: Locks the "test" account using `usermod -L test`


## Testing and Validation

#### Test 1: Legitimate Login (From the Allowed Network)

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Legit%20SSH.jpg" width="700">
  <br>
  <strong>SSH login from an allowed range (192.168.1.0/24)</strong>
</p>

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/SSH%20Legit%20Wazuh.jpg" width="700">
  <br>
  <strong>Allowed SSH login in Wazuh</strong>
</p>


#### Test 2: Unauthorized Login ( Login Outside of the Allowed Range )

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Unauthorized%20SSH.jpg" width="700">
  <br>
  <strong>SSH login from outside of the allowed range</strong>
</p>

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Active%20Response%20SSH.jpg" width="700">
  <br>
  <strong>The Active Response is Immediately Triggered</strong>
</p>


#### Verifying account lockout and firewall drop

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Account%20Lockout.jpg" width="700">
  <br>
  <strong>The account "test" is locked</strong>
</p>

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Firewall-Drop.jpg" width="700">
  <br>
  <strong>As we can see from the IpTables, the unauthorized IP got dropped</strong>
</p>



