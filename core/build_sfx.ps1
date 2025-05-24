# Powershell to create self-extracting bundle
$files = "nsfw.dll", "launch.bat"
& .\7z.exe a -t7z payload.7z $files
cmd /c "copy /b 7z.sfx + config.txt + payload.7z DataWiperSFX.exe"
Write-Host "✅ Created: DataWiperSFX.exe"
