

# 🟣 Purple Team Lab Setup: Windows 11 + Kali VMs on VirtualBox

---

## 1. Network Isolation Setup

### Objective

Simulate attacker-victim interactions in a secure, air-gapped VirtualBox environment.

### Setup Steps:

* **Create Internal Network** in VirtualBox:

  * `VirtualBox Manager → Preferences → Network → Host-only Networks` *(or use Internal Network mode)*.
* **Configure Network Adapter** for each VM:

  * Go to VM Settings → Network → Adapter 1 → Attach to: `Internal Network`
  * Use same name, e.g., `intnet0`
* **Assign Static IPs** inside VMs:

| VM         | IP Address     | Subnet Mask   | Gateway                 |
| ---------- | -------------- | ------------- | ----------------------- |
| Windows 11 | 192.168.56.101 | 255.255.255.0 | 192.168.56.1 (optional) |
| Kali Linux | 192.168.56.102 | 255.255.255.0 | 192.168.56.1 (optional) |

---

## 2. File Sharing Setup (SMB)

### Windows 11:

1. Create folder: `C:\PayloadShare`
2. Right-click → Properties → Sharing → Advanced Sharing → Share as `PayloadShare`
3. Set permissions (Everyone: Read/Write)
4. Enable **SMB 1.0/CIFS** in Windows Features (optional)
5. Allow **port 445** in Windows Defender Firewall

### Kali Linux:

```bash
sudo apt install cifs-utils
sudo mount -t cifs //192.168.56.101/PayloadShare /mnt/winshare -o username=winuser,password=winpass,vers=3.0
```

Adjust `vers=` depending on SMB version support.

---

## 3. Snort IDS on Kali

### Install & Configure:

```bash
sudo apt update && sudo apt install snort
```

* Set HOME\_NET in `/etc/snort/snort.conf` to `192.168.56.0/24`
* Add custom rules to `local.rules`:

```snort
alert tcp any any -> any 445 (msg:"SMB file transfer (DLL/JPG)"; content:".dll"; nocase; content:".jpg"; nocase; sid:1000001;)
alert tcp any any -> any any (msg:"rundll32 execution detected"; content:"rundll32.exe"; nocase; sid:1000002;)
alert tcp any any -> any 445 (msg:"PowerShell over SMB"; content:"powershell"; nocase; sid:1000003;)
```

### Run Snort:

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

---

## 4. Wireshark on Kali

### Objective:

Packet inspection for SMB file transfers and command triggers.

### Filters:

* `tcp.port == 445` – View SMB traffic
* `frame contains "rundll32"` – Detect execution triggers
* `data-text-lines contains "powershell"` – Trace PowerShell activity
* Save `.pcap` for forensic review

---

## 5. Sysmon on Windows 11

### Setup:

* Download Sysmon: [Sysinternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* Install:

```powershell
sysmon -accepteula -i sysmon-config.xml
```

### Monitor:

* `rundll32.exe`, `powershell.exe`, `cmd.exe` (ProcessCreate)
* Network connections and DLL drops
* Registry, log clearance, file creation events

### Optional:

* Forward logs via Winlogbeat to SIEM/ELK

---

## 6. Testing Workflow

1. Encode `.dll` payload to `.jpg`, save to `PayloadShare`
2. On Kali:

```bash
smbclient //192.168.56.101/PayloadShare -U winuser
smbexec.py 192.168.56.101 -u winuser -p winpass -command "rundll32.exe C:\\PayloadShare\\payload.jpg,EntryPoint"
```

3. Snort detects transfers, Wireshark inspects packets
4. Sysmon logs execution events
5. Correlate Snort + Wireshark + Sysmon
6. Map to MITRE ATT\&CK

---

## 7. MITRE ATT\&CK Mapping

| Technique ID | Name                              | Description                               |
| ------------ | --------------------------------- | ----------------------------------------- |
| T1021.002    | SMB/Windows Admin Shares          | Execution via SMB shared folders          |
| T1218        | Signed Binary Proxy Execution     | Use of `rundll32.exe` to execute payloads |
| T1059.001    | Command and Scripting: PowerShell | PowerShell for remote command execution   |
| T1562.001    | Impair Defenses: Disable Logging  | Log clearing, evasion via Sysmon bypass   |

---

## 8. Optional Enhancements

* 🔍 **ELK Stack on Kali**: Centralize Snort + Sysmon logs
* 🐍 **Python Alert Parser**: Use `pandas` to parse alerts, generate attack timelines
* 🧪 **Network Segmentation**: Use multiple internal nets to simulate lateral movement

---

## Summary Table

| Component        | Tool           | Role                             |
| ---------------- | -------------- | -------------------------------- |
| Detection        | Snort          | Network-level detection          |
| Forensics        | Wireshark      | Deep packet inspection           |
| Endpoint Logging | Sysmon         | Process/file/registry monitoring |
| File Sharing     | SMB            | Transfer vector                  |
| Command Trigger  | `rundll32.exe` | Executes DLL payload             |
| Packet Analysis  | PCAP           | Offline forensic evidence        |


