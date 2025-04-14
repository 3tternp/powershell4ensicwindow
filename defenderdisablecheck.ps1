Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | 
Where-Object { $_.Id -eq 5001 } | 
Select-Object -First 1 -Property TimeCreated | 
ForEach-Object { $_.TimeCreated.ToString("hh:mm:ss tt") }
