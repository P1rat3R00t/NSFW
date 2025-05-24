
# Purple Team Lab Setup: Windows 11 + Kali VMs on VirtualBox

---

## 1. Network Isolation Setup

- Use VirtualBox **Internal Network** adapter named `intnet0`
- Assign static IPs:

| VM        | IP Address      | Subnet Mask     |
|-----------|-----------------|-----------------|
| Windows 11| 192.168.56.101  | 255.255.255.0   |
| Kali Linux| 192.168.56.102  | 255.255.255.0   |

---

## 2. Windows 11 SMB Share Setup

- Create folder `C:\PayloadShare`
- Share it as `PayloadShare` with Read/Write permissions
- Ensure SMB file sharing enabled and firewall allows port 445
- Use Windows credentials for access

---

## 3. Kali SMB Mount

```bash
sudo apt install cifs-utils
sudo mount -t cifs //192.168.56.101/PayloadShare /mnt/winshare -o username=winuser,password=winpass,vers=3.0
````

---

## 4. Snort IDS Setup on Kali

### Install Snort

```bash
sudo apt update
sudo apt install snort
```

### Configuration: `/etc/snort/snort.conf`

Set HOME\_NET:

```conf
ipvar HOME_NET 192.168.56.0/24
```

Include local rules:

```conf
include $RULE_PATH/local.rules
```

### Local Rules File: `/etc/snort/rules/local.rules`

```snort
alert tcp 192.168.56.0/24 any -> 192.168.56.0/24 445 (msg:"SMB file transfer with DLL/JPG detected"; flow:established,to_server; content:".dll"; nocase; content:".jpg"; nocase; classtype:trojan-activity; sid:1000001; rev:3;)
alert tcp any any -> any any (msg:"Potential rundll32.exe remote execution"; flow:established; content:"rundll32.exe"; nocase; classtype:policy-violation; sid:1000002; rev:4;)
alert tcp any any -> any 445 (msg:"PowerShell command over SMB"; flow:established,to_server; content:"powershell"; nocase; classtype:attempted-admin; sid:1000003; rev:3;)
```

### Running Snort

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

Replace `eth0` with your Kali internal network interface.

---

## 5. Wireshark Usage on Kali

* Capture traffic on internal interface
* Use filters like:

```
smb2
frame contains "rundll32"
tcp.port == 445
data-text-lines contains "powershell"
```

---

## 6. Sysmon Setup on Windows 11

### Download and install:

[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

### Example `sysmon-config.xml`

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="contains">rundll32.exe</Image>
      <Image condition="contains">powershell.exe</Image>
      <Image condition="contains">cmd.exe</Image>
    </ProcessCreate>
    <NetworkConnect onmatch="include"/>
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">.dll</TargetFilename>
      <TargetFilename condition="contains">.jpg</TargetFilename>
    </FileCreate>
    <EventLog onmatch="include">
      <EventID>1102</EventID> <!-- Event Log Clear -->
    </EventLog>
    <RegistryEvent onmatch="include"/>
  </EventFiltering>
</Sysmon>
```

### Install Sysmon with config

```powershell
sysmon -accepteula -i sysmon-config.xml
```

---

## 7. Testing Workflow

1. Encode fileless wiper DLL as `.jpg`, drop into `PayloadShare`
2. Mount share on Kali, access file
3. Trigger execution remotely via SMB exec tools or PSExec variants:

```bash
smbexec.py -target 192.168.56.101 -command "rundll32.exe C:\\PayloadShare\\payload.jpg,EntryPoint"
```

4. Monitor alerts on Snort console
5. Inspect network traffic via Wireshark
6. Review Sysmon logs for suspicious activity

---

## 8. MITRE ATT\&CK Techniques Reference

| Technique ID | Technique Name                |
| ------------ | ----------------------------- |
| T1021.002    | SMB Remote Execution          |
| T1218        | Signed Binary Proxy Execution |
| T1059.001    | PowerShell                    |
| T1562.001    | Impair Defenses               |

---

## 9. Python Snort Alert Parser (Starter)

Save as `snort_alert_parser.py`

```python
import re

def parse_snort_alerts(alert_file):
    alerts = []
    with open(alert_file, 'r') as f:
        for line in f:
            # Example pattern to extract alert message and sid
            match = re.search(r'\[.*\] \[.*\] \[.*\] \[([^\]]+)\] (.*)', line)
            if match:
                sid = match.group(1)
                msg = match.group(2)
                alerts.append({'sid': sid, 'msg': msg})
    return alerts

if __name__ == "__main__":
    alerts = parse_snort_alerts('/var/log/snort/alert')
    for alert in alerts:
        print(f"SID: {alert['sid']}, Message: {alert['msg']}")
```

---

## 10. Useful Links

* VirtualBox Networking: [https://www.virtualbox.org/manual/ch06.html#network\_internal](https://www.virtualbox.org/manual/ch06.html#network_internal)
* SMB File Sharing Windows: [https://docs.microsoft.com/en-us/windows-server/storage/file-server/file-server-overview](https://docs.microsoft.com/en-us/windows-server/storage/file-server/file-server-overview)
* Snort Official: [https://snort.org/](https://snort.org/)
* Sysmon Download & Docs: [https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* MITRE ATT\&CK Framework: [https://attack.mitre.org/](https://attack.mitre.org/)


