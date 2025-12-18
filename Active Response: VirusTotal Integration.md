## Overview of this Use Case
Integrated VirusTotal's threat intelligence API with Wazuh to enable real-time malware detection and automated removal on Windows endpoints. When File Integrity Monitoring (FIM) detects a new file in monitored directories, the hash is immediately queried against VirusTotal's database. Files identified as malicious trigger an Active Response script that deletes the threat before execution and generates an alert.

## Architecture
```
Windows Downloads Folder
        ↓
   File Created
        ↓
 Wazuh FIM (Rule 550)
        ↓
 VirusTotal API Query
        ↓
  Malicious Match (Rule 87105)
        ↓
 Active Response Script
        ↓
   File Deleted + Alert in Discord
```

**Key Components:**
- **FIM Module:** Monitors file system changes in real-time
- **VirusTotal API:** Threat intelligence lookup
- **Active Response:** Python script for file removal available in the official Wazuh documentation
- **Alerting:** Wazuh dashboard + Discord webhook

## Implementation

### Step 1: enable real-time FIM for the Downloads folder in the desired endpoint.

The bellow snippet has to be added to the **C:\Program Files (x86)\ossec-agent\ossec.conf** on the windows endpoint.
``` <directories realtime="yes">C:\Users\<USER_NAME>\Downloads</directories> ```

### Step 2: Integrate VirusTotal into Wazuh

The next snippet has to be added into the ``` /var/ossec/etc/ossec.conf ``` on the wazuh server.
```xml
<ossec_config>
  <integration>
    <name>virustotal</name>
    <api_key><YOUR_VIRUS_TOTAL_API_KEY></api_key> 
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>

```
### Step 3: Create the script that removes the malicious file.

The script is available in the official Wazuh Documentation.

```python
# Copyright (C) 2015-2025, Wazuh Inc.
# All rights reserved.

import os
import sys
import json
import datetime
import stat
import tempfile
import pathlib

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name + ": " + msg +"\n")

def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    msg_obj = message()
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        msg_obj.command = OS_INVALID
        return msg_obj

    msg_obj.alert = data
    command = data.get("command")

    if command == "add":
        msg_obj.command = ADD_COMMAND
    elif command == "delete":
        msg_obj.command = DELETE_COMMAND
    else:
        msg_obj.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return msg_obj

def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})
    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return OS_INVALID

    action = data.get("command")
    if action == "continue":
        return CONTINUE_COMMAND
    elif action == "abort":
        return ABORT_COMMAND
    else:
        write_debug_file(argv[0], "Invalid value of 'command'")
        return OS_INVALID

def secure_delete_file(filepath_str, ar_name):
    filepath = pathlib.Path(filepath_str)

    # Reject NTFS alternate data streams
    if '::' in filepath_str:
        raise Exception(f"Refusing to delete ADS or NTFS stream: {filepath_str}")

    # Reject symbolic links and reparse points
    if os.path.islink(filepath):
        raise Exception(f"Refusing to delete symbolic link: {filepath}")

    attrs = os.lstat(filepath).st_file_attributes
    if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise Exception(f"Refusing to delete reparse point: {filepath}")

    resolved_filepath = filepath.resolve()

    # Ensure it's a regular file
    if not resolved_filepath.is_file():
        raise Exception(f"Target is not a regular file: {resolved_filepath}")

  # Perform deletion
    os.remove(resolved_filepath)

def main(argv):
    write_debug_file(argv[0], "Started")
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:
        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]["id"]]
        action = send_keys_and_check_message(argv, keys)

        if action != CONTINUE_COMMAND:
            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        try:
            file_path = alert["data"]["virustotal"]["source"]["file"]
            if os.path.exists(file_path):
                secure_delete_file(file_path, argv[0])
                write_debug_file(argv[0], json.dumps(msg.alert) + " Successfully removed threat")
            else:
                write_debug_file(argv[0], f"File does not exist: {file_path}")
        except OSError as error:
            write_debug_file(argv[0], json.dumps(msg.alert) + "Error removing threat")
        except Exception as e:
            write_debug_file(argv[0], f"{json.dumps(msg.alert)}: Error removing threat: {str(e)}")
    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)
```

This script then has to be transformed into a .exe file using pyinstaller and after copied to the active-response folder on the endpoint to monitor ``` C:\Program Files (x86)\ossec-agent\active-response\bin ```

### Step 4: Enable Active Response and trigger the **remove-threat.exe** executable when the VirusTotal query returns positive matches for threats

```xml
<ossec_config>
  <command>
    <name>remove-threat</name>
    <executable>remove-threat.exe</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>
</ossec_config>
```

### Step 5:  Adding the following rule into the ```/var/ossec/etc/rules/local_rules.xml```  to alert about the Active Response results

```xml
<group name="virustotal,">
  <rule id="100092" level="12">
      <if_sid>657</if_sid>
      <match>Successfully removed threat</match>
      <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
```

## Testing and Validation


I tested the Use Case with a benign EICAR file that I downloaded from Ikarus Software.

After the file was downloaded almost immediately got deleted by the active response as can be seen in the screen shot below.

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/VirusTotal%20Response.jpeg" width="700">
  <br>
  <strong>Alerts in Wazuh Dashboard</strong>
</p>

Also the alert triggered through the discord webhook

<p align="center">
  <img src="https://github.com/Bino-Albino/Detection-and-Response-Homelab/blob/main/Assets/Discord-Alert.jpg" width="700">
  <br>
  <strong>Discord Integration</strong>
</p>




