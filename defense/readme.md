

# Simplified Purple Team Lab Setup: Win11 + Kali VMs on VirtualBox

---

## 1. Network Isolation Setup

* **Create an internal VirtualBox network** (e.g., `intnet0`)

  * Both Win11 and Kali VMs attached to this **internal-only** network.
  * No internet or host OS access; complete isolation for safe testing.

* **IP Configuration:**

  * Assign static IPs:

    * Win11: `192.168.56.101`
    * Kali: `192.168.56.102`

---

## 2. File Sharing Setup (Net Share)

* On **Windows 11 VM**, create a network share folder:

  * Share a directory where you’ll drop your `.jpg`-encoded fileless wiper DLL.
  * Ensure SMB file sharing enabled in Windows Features.
  * Permissions: Allow Kali VM read/write access.

* On **Kali VM**, mount the Windows share via SMB:

  ```
  sudo mount -t cifs //192.168.56.101/sharename /mnt/winshare -o username=winuser,password=winpass
  ```

---

## 3. Snort Deployment on Kali

* Install Snort on Kali:

  ```
  sudo apt update && sudo apt install snort
  ```

* Configure Snort to monitor the internal interface connected to `intnet0`.

* Use custom rules targeting SMB file transfers, `rundll32.exe` execution signatures, and network PowerShell commands.

* Start Snort in IDS mode on the internal interface:

  ```
  sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
  ```

---

## 4. Wireshark Usage

* Run Wireshark on Kali VM to capture all network traffic on the internal interface.

* Use display filters for SMB and suspicious traffic:

  * `smb2` — SMBv2 protocol
  * `frame contains "rundll32"` — Detect payload triggers
  * `tcp.port == 445` — SMB traffic port filter

* Analyze suspicious packets and export PCAPs for forensic review.

---

## 5. Windows 11 Sysmon Configuration

* Deploy Sysmon on Win11 with a config tuned to detect your fileless wiper tactics:

  * Monitor process creations for `rundll32.exe`
  * Network connections
  * Event log clearing or registry changes

* Forward Sysmon logs locally or via Winlogbeat for offline analysis.

---

## 6. Testing Workflow

1. **Deploy your `.jpg` file with encoded DLL payload** on the Windows share.

2. From Kali, trigger remote execution via SMB or a remote command invoking `rundll32.exe` on the target file in the share.

3. **Snort and Wireshark** monitor network traffic, detect the SMB transfer and exec attempt.

4. **Sysmon** logs process creation and suspicious activity on Win11.

5. Analyze Snort alerts, Wireshark captures, and Sysmon logs for correlations.

6. Reference MITRE ATT\&CK techniques throughout:

| Technique                             | Example                                          |
| ------------------------------------- | ------------------------------------------------ |
| T1021.002 (SMB)                       | Executing payload remotely via SMB share         |
| T1218 (Signed Binary Proxy Execution) | Using rundll32.exe to launch DLL payload         |
| T1059.001 (PowerShell)                | Possible PowerShell encoded commands (if used)   |
| T1562.001 (Impair Defenses)           | Event log clearing or tampering by wiper payload |

---

## 7. Optional Enhancements

* Use **Elastic Stack** on Kali for centralized logging and correlation (optional).

* Automate Snort alert parsing with a Python script for alert timelines.

* Apply network segmentation and VLAN tagging in VirtualBox for multi-subnet tests.

---

# Summary

| Component                   | Role                                 | Details                           |
| --------------------------- | ------------------------------------ | --------------------------------- |
| VirtualBox internal network | Isolated test network                | Prevents external interference    |
| Windows 11 VM               | Target of fileless wiper via SMB     | Shared folder for payload drop    |
| Kali VM                     | Attacker & sensor (Snort, Wireshark) | Monitoring and launching attack   |
| Snort                       | Network IDS on Kali                  | Detects SMB file transfers & exec |
| Wireshark                   | Packet capture on Kali               | Deep packet inspection            |
| Sysmon                      | Endpoint detection on Win11          | Process, network, log monitoring  |

