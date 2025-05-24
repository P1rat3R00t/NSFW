

#  Purple Team Lab Setup: Windows 11 + Kali VMs on VirtualBox

---

## 1. Network Isolation Setup

### Objective

Create a fully isolated, internal network within VirtualBox to simulate attacker-victim communication securely, without exposing your host OS or external networks.

### Steps

* **Create an internal VirtualBox network adapter:**

  Open VirtualBox Manager → Preferences → Network → Host-only Networks
  *(Alternatively, use the internal network type directly attached to VMs for pure isolation.)*

* **Attach both Windows 11 and Kali VMs to the same internal network:**

  * Edit VM settings → Network → Enable Network Adapter →
  * Attach to: **Internal Network**
  * Name: `intnet0` (or any unique identifier)

* **Assign static IPs:**

  Manually configure the network adapters inside each VM:

  | VM         | IP Address     | Subnet Mask   | Gateway                 |
  | ---------- | -------------- | ------------- | ----------------------- |
  | Windows 11 | 192.168.56.101 | 255.255.255.0 | 192.168.56.1 (optional) |
  | Kali Linux | 192.168.56.102 | 255.255.255.0 | 192.168.56.1 (optional) |

  > *Example: In Windows 11, use `ncpa.cpl` → right-click adapter → Properties → IPv4 → Set static IP.*
  > *In Kali, edit `/etc/network/interfaces` or use `nmcli`.*

### Resources

* VirtualBox Networking Modes:
  [https://www.virtualbox.org/manual/ch06.html#network\_internal](https://www.virtualbox.org/manual/ch06.html#network_internal)
* Configuring Static IPs in Windows 11:
  [https://docs.microsoft.com/en-us/windows-server/networking/technologies/ipam/ipam-network-ip-address-management](https://docs.microsoft.com/en-us/windows-server/networking/technologies/ipam/ipam-network-ip-address-management)
* Configuring Static IPs in Kali Linux:
  [https://linuxhint.com/set-static-ip-kali-linux/](https://linuxhint.com/set-static-ip-kali-linux/)

---

## 2. File Sharing Setup (Net Share)

### Objective

Enable file exchange between Kali and Windows 11 using SMB to deliver your encoded fileless wiper DLL safely inside the isolated network.

### Windows 11 VM (Share Setup)

1. Create a folder, e.g., `C:\PayloadShare`

2. Right-click folder → Properties → Sharing → Advanced Sharing

   * Check "Share this folder"
   * Name it `PayloadShare`

3. Click Permissions → Add your Kali user or allow "Everyone" with Read/Write access (for lab simplicity).

4. Ensure **SMB 1.0/CIFS File Sharing Support** is enabled via Windows Features (for compatibility).
   (Optional: You can use SMBv2/v3 but check compatibility with your Kali SMB client.)

5. Adjust Windows Firewall to allow SMB traffic (port 445) on the internal network.

### Kali VM (Mount Share)

```bash
sudo apt install cifs-utils    # if not already installed
sudo mount -t cifs //192.168.56.101/PayloadShare /mnt/winshare -o username=winuser,password=winpass,vers=3.0
```

> *Replace `winuser` and `winpass` with Windows credentials.*
> *Use `vers=2.0` or `vers=1.0` if necessary depending on SMB version support.*

### Resources

* Windows SMB File Sharing:
  [https://docs.microsoft.com/en-us/windows-server/storage/file-server/file-server-overview](https://docs.microsoft.com/en-us/windows-server/storage/file-server/file-server-overview)
* Mount SMB Share on Linux:
  [https://wiki.samba.org/index.php/Mounting\_samba\_shares](https://wiki.samba.org/index.php/Mounting_samba_shares)

---

## 3. Snort Deployment on Kali

### Objective

Use Snort IDS on Kali to detect suspicious SMB file transfers, execution triggers like `rundll32.exe`, and PowerShell remote commands.

### Installation

```bash
sudo apt update
sudo apt install snort
```

During installation, Snort may prompt for the network interface—select the internal network interface (e.g., `eth0`).

### Configuration

1. Edit `/etc/snort/snort.conf`

   * Set HOME\_NET to `192.168.56.0/24` to cover your isolated lab subnet.
   * Include custom rules by adding:

   ```
   include $RULE_PATH/local.rules
   ```

2. Create `local.rules` (example rules expanded from earlier):

```snort
alert tcp 192.168.56.0/24 any -> 192.168.56.0/24 445 (msg:"SMB file transfer with DLL/JPG detected"; flow:established,to_server; content:".dll"; nocase; content:".jpg"; nocase; classtype:trojan-activity; sid:1000001; rev:3;)
alert tcp any any -> any any (msg:"Potential rundll32.exe remote execution"; flow:established; content:"rundll32.exe"; nocase; classtype:policy-violation; sid:1000002; rev:4;)
alert tcp any any -> any 445 (msg:"PowerShell command over SMB"; flow:established,to_server; content:"powershell"; nocase; classtype:attempted-admin; sid:1000003; rev:3;)
```

3. Start Snort in IDS mode on the interface:

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

### Resources

* Snort official docs:
  [https://snort.org/documents](https://snort.org/documents)
* Writing Snort Rules Tutorial:
  [https://www.snort.org/documents/snort-users-manual](https://www.snort.org/documents/snort-users-manual)
* Sample Snort Rules for SMB Monitoring:
  [https://github.com/ntop/nDPI/blob/dev/examples/snort/](https://github.com/ntop/nDPI/blob/dev/examples/snort/)
* Kali Snort Setup Guide:
  [https://www.kali.org/tools/snort/](https://www.kali.org/tools/snort/)

---

## 4. Wireshark Usage

### Objective

Perform deep packet inspection of network traffic inside your isolated lab to visually inspect SMB transfers and suspicious command executions.

### Usage

* Run Wireshark on Kali, select the internal network interface (`eth0` or similar).

* Use display filters:

  * `smb2` — capture SMBv2 protocol packets
  * `frame contains "rundll32"` — locate payload trigger commands
  * `tcp.port == 445` — filter all SMB traffic
  * `data-text-lines contains "powershell"` — spot PowerShell commands in network data

* Save suspicious packets as `.pcap` files for offline forensic analysis or sharing.

### Resources

* Wireshark Official Site:
  [https://www.wireshark.org/](https://www.wireshark.org/)
* Wireshark Display Filters Reference:
  [https://wiki.wireshark.org/DisplayFilters](https://wiki.wireshark.org/DisplayFilters)
* SMB Protocol Analysis:
  [https://wiki.wireshark.org/SMB](https://wiki.wireshark.org/SMB)

---

## 5. Windows 11 Sysmon Configuration

### Objective

Deploy Sysmon on Windows 11 to monitor and log endpoint activities relevant to fileless wiper DLL execution and persistence behaviors.

### Setup

1. Download Sysmon from Microsoft Sysinternals:
   [https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

2. Deploy with advanced config (example `sysmon-config.xml`):

```powershell
sysmon -accepteula -i sysmon-config.xml
```

### Key Configurations

* Log process creations of `rundll32.exe`, `powershell.exe`, `cmd.exe`
* Monitor network connections and file creation/deletion (.dll, .jpg)
* Detect event log clearing and registry persistence modifications

### Forwarding

* Optionally use Winlogbeat or other Windows Event Forwarders to send Sysmon logs to your Kali ELK stack or SIEM.

### Resources

* Sysmon Documentation and Configurations:
  [https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* Sysmon Config Examples:
  [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
* Winlogbeat Windows Event Forwarding:
  [https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-installation.html](https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-installation.html)

---

## 6. Testing Workflow

### Step-by-step

1. Encode your fileless wiper DLL into a `.jpg` file and drop it into the Windows shared folder (`PayloadShare`).

2. From Kali, mount the share and trigger execution remotely using SMB or a remote command, e.g.:

   ```bash
   smbclient //192.168.56.101/PayloadShare -U winuser
   # Then remotely trigger rundll32 execution via SMB exec or a PS exec tool:
   smbexec.py -target 192.168.56.101 -command "rundll32.exe C:\\PayloadShare\\payload.jpg,EntryPoint"
   ```

3. Snort on Kali will detect the SMB file transfer and execution commands in real time.

4. Wireshark captures the network traffic for packet-level analysis.

5. Sysmon on Windows logs the execution, network connections, and suspicious events locally.

6. Collect and correlate data from Snort alerts, Wireshark PCAPs, and Sysmon logs to validate attack detection.

7. Map observations to MITRE ATT\&CK techniques for threat intelligence and reporting.

---

## 7. MITRE ATT\&CK Mapping Examples

| Technique ID | Name                          | Description                            |
| ------------ | ----------------------------- | -------------------------------------- |
| T1021.002    | SMB Remote Execution          | Executing payload via SMB file sharing |
| T1218        | Signed Binary Proxy Execution | Use of \`rundll                        |


32.exe\` to load and execute DLLs          |
\| T1059.001    | PowerShell                       | Execution of PowerShell commands remotely or locally    |
\| T1562.001    | Impair Defenses                  | Event log clearing or tampering to evade detection       |

More on MITRE ATT\&CK:
[https://attack.mitre.org/](https://attack.mitre.org/)

---

## 8. Optional Enhancements

* **Elastic Stack (ELK)** on Kali:

  * Deploy Elasticsearch, Logstash, and Kibana for centralized log aggregation, visualization, and alerting.
  * Forward Snort and Sysmon logs to ELK for unified analysis.

* **Python Alert Parser:**

  * Automate Snort alert log parsing.
  * Generate timelines and correlation reports.
  * Use libraries like `pandas` and `matplotlib` for analysis.

* **Network Segmentation:**

  * Use VirtualBox VLAN tagging (experimental) or multiple internal networks.
  * Simulate multi-subnet environments and lateral movement scenarios.

---

# Summary Table

| Component                   | Role                                     | Details/Tools                            | URL/References                                                                                                                                                                       |
| --------------------------- | ---------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| VirtualBox Internal Network | Isolated test network                    | Internal Network adapter (`intnet0`)     | [https://www.virtualbox.org/manual/ch06.html#network\_internal](https://www.virtualbox.org/manual/ch06.html#network_internal)                                                        |
| Windows 11 VM               | Target of fileless payload delivery      | Shared folder, SMB enabled               | [https://docs.microsoft.com/en-us/windows-server/storage/file-server/file-server-overview](https://docs.microsoft.com/en-us/windows-server/storage/file-server/file-server-overview) |
| Kali VM                     | Attacker and Sensor platform             | Snort IDS, Wireshark, SMB client         | [https://kali.org/tools/snort/](https://kali.org/tools/snort/) <br> [https://www.wireshark.org/](https://www.wireshark.org/)                                                         |
| Snort                       | Network Intrusion Detection System (IDS) | Custom SMB and execution rules           | [https://snort.org/](https://snort.org/)                                                                                                                                             |
| Wireshark                   | Packet Capture and Analysis              | Real-time inspection                     | [https://www.wireshark.org/](https://www.wireshark.org/)                                                                                                                             |
| Sysmon                      | Endpoint Monitoring & Detection          | Process creation, network, log tampering | [https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)                                                     |

