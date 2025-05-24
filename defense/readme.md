

# Purple Team Exercise Full Setup & Workflow

---

## 1. **Network and VM Setup**

* **Hardware & Network:**

  * Spectrum Modem (EN2251) + SAX1V1K WiFi 6 Router (inactive, isolated network).
  * Connect your host PC to this network or isolate traffic to a virtual network inside VirtualBox.

* **Virtual Machines:**

  * Windows 11 VM: Target system with SMB shares configured.
  * Kali Linux VM: Defensive/offensive toolset, including Snort and Wireshark installed.

* **VirtualBox Network Configuration:**

  * Use **Host-Only Adapter** or **Internal Network** mode to simulate isolated environment.
  * Ensure Kali VM can see all traffic to/from Windows 11 VM for monitoring.

---

## 2. **Windows 11 Target Preparation**

* Configure **SMB shares** accessible by Kali VM. Place the encoded payload (JPG with embedded wiper) here.

* Enable **Windows Event Logging:**

  * Process creation (Sysmon or built-in Windows logs).
  * Network connections and SMB session events.
  * Event log clearing monitoring.

* Apply basic **AppLocker or WDAC policies** to restrict usage of `rundll32.exe` and PowerShell for mitigation testing.

---

## 3. **Snort Setup on Kali VM**

* Install Snort:

  ```bash
  sudo apt update && sudo apt install snort
  ```

* Place the custom ruleset (`purpleteam-fileless-wiper.rules`) into `/etc/snort/rules/`.

* Edit `/etc/snort/snort.conf` to include the rules:

  ```plaintext
  include $RULE_PATH/purpleteam-fileless-wiper.rules
  ```

* Start Snort in IDS mode, listening on the appropriate interface:

  ```bash
  sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
  ```

* Tail the alert logs for matches.

---

## 4. **Wireshark Setup**

* Install Wireshark on host or Kali VM.

* During the exercise, run live capture on the network interface observing Windows VM traffic.

* Use filters such as:

  ```
  smb2.file_name contains ".jpg"
  smb2.cmd == 0x05 and smb2.file_name contains "rundll32"
  smb2.file_name contains "pipe"
  frame contains "powershell"
  ```

* Optionally set color rules for quicker spotting.

---

## 5. **Execute the Fileless Wiper Test**

* From Kali or an authorized host, trigger remote execution of the embedded payload via:

  ```powershell
  rundll32.exe \\windows_vm_ip\share\encoded_payload.jpg,EntryPoint
  ```

* This activates the wiper encoded inside the JPG, executing fileless in Windows memory.

---

## 6. **Detection & Analysis**

* **Snort:**

  * Watch for alerts triggered by SMB file transfers, `rundll32.exe` execution, PowerShell commands, and Named Pipe usage.

* **Wireshark:**

  * Inspect packet captures for unusual SMB file activity, commands referencing `rundll32.exe` or PowerShell, and named pipes.

* **Windows Event Logs:**

  * Confirm process creation logs (`rundll32.exe` launch).
  * Look for suspicious network activity and log clearing attempts.

* Correlate Snort alerts with Wireshark captures and Windows logs to build a timeline and verify detection efficacy.

---

## 7. **Mitigation & Hardening**

* Apply or tune **AppLocker/WDAC** to block unauthorized `rundll32.exe` or PowerShell from SMB shares.

* Enable SMB **signing and encryption** to mitigate tampering.

* Monitor and alert on **event log clearance** or other suspicious system modifications.

---

## 8. **MITRE ATT\&CK Mapping**

| Technique ID | Technique Name                                | Description & Detection                                                                                      |
| ------------ | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| T1021.002    | Remote Services: SMB/Windows Admin Shares     | Fileless payload executed via SMB shares (`rundll32.exe`). Snort detects SMB payload and execution attempts. |
| T1059.001    | Command and Scripting Interpreter: PowerShell | Detection of embedded PowerShell commands in traffic and process logs.                                       |
| T1565        | Data Manipulation                             | Wiper activity—file destruction via payload.                                                                 |
| T1562.001    | Impair Defenses: Disable or Modify Tools      | Detection of event log clearing attempts on Windows.                                                         |

---

## Summary

| Step                       | Purpose                                    |
| -------------------------- | ------------------------------------------ |
| VM and network setup       | Isolate and monitor network traffic        |
| Snort deployment           | Automated network intrusion detection      |
| Wireshark live capture     | Deep packet inspection and manual analysis |
| Windows target hardening   | Apply mitigation controls                  |
| Execute test payload       | Validate detection and defense mechanisms  |
| Analyze and correlate logs | Ensure comprehensive visibility            |
| MITRE ATT\&CK mapping      | Structure detection coverage and gaps      |


