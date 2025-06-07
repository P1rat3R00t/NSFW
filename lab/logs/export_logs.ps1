# Songbird Log Export Script
# Author: LamWhite Red Team
# Target: Windows 11 (Fileless / LOLBins / Spooler Test Systems)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$baseDir = "$env:USERPROFILE\songbird_logs\$timestamp"

# Create output directory
New-Item -ItemType Directory -Path $baseDir -Force | Out-Null

# Define logs to export
$logs = @("Security", "System", "Application", "Microsoft-Windows-PrintService/Operational")

foreach ($log in $logs) {
    $evtxOut = "$baseDir\$log.evtx"
    $jsonOut = "$baseDir\$log.json"

    # Export EVTX
    wevtutil epl "$log" "$evtxOut"

    # Export JSON (structured events)
    Get-WinEvent -LogName $log -MaxEvents 500 |
        ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                ProviderName = $_.ProviderName
                Id = $_.Id
                LevelDisplayName = $_.LevelDisplayName
                Message = $_.Message
            }
        } | ConvertTo-Json -Depth 3 | Out-File -Encoding UTF8 $jsonOut
}

Write-Output "✅ Logs exported to: $baseDir"