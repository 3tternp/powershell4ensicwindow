# ForensicCollector.ps1 - Basic Digital Forensic Triage Script
# Author: ChatGPT
# Tested on: Windows 10/11, PowerShell 5+

# Output folder
$OutputDir = "$env:USERPROFILE\Forensic_Report_$((Get-Date).ToString('yyyyMMdd_HHmmss'))"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Write-Host "Collecting forensic data... Output directory: $OutputDir"

# System Info
systeminfo > "$OutputDir\SystemInfo.txt"
Get-ComputerInfo > "$OutputDir\ComputerInfo.txt"

# Users and Groups
net user > "$OutputDir\Users.txt"
net localgroup > "$OutputDir\Groups.txt"
net user /domain > "$OutputDir\DomainUsers.txt" 2>$null

# Running Processes
Get-Process | Sort-Object CPU -Descending | Out-File "$OutputDir\Processes.txt"

# Network Configuration
ipconfig /all > "$OutputDir\NetworkConfig.txt"
Get-NetTCPConnection | Out-File "$OutputDir\TCPConnections.txt"
netstat -ano > "$OutputDir\Netstat.txt"

# Startup Items
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User | 
    Out-File "$OutputDir\StartupItems.txt"

# Scheduled Tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State | Out-File "$OutputDir\ScheduledTasks.txt"

# Services
Get-Service | Where-Object { $_.Status -eq 'Running' } | Out-File "$OutputDir\RunningServices.txt"

# Recent Event Logs (last 24 hours)
$Since = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Since} -MaxEvents 1000 |
    Out-File "$OutputDir\SecurityEvents.txt"

Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Since} -MaxEvents 500 |
    Out-File "$OutputDir\SystemEvents.txt"

# Logged-on Users
quser > "$OutputDir\LoggedOnUsers.txt" 2>$null

# External Devices Mounted
Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 -or $_.DriveType -eq 5 } |
    Select-Object DeviceID, VolumeName, FileSystem, Size | Out-File "$OutputDir\MountedDevices.txt"

# Installed Applications
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Out-File "$OutputDir\InstalledApps.txt"

# Hash of Critical Binaries
$CriticalPaths = @(
    "$env:SystemRoot\System32\cmd.exe",
    "$env:SystemRoot\System32\powershell.exe",
    "$env:SystemRoot\explorer.exe"
)

foreach ($file in $CriticalPaths) {
    if (Test-Path $file) {
        $hash = Get-FileHash -Algorithm SHA256 -Path $file
        $hash | Out-File "$OutputDir\Hashes.txt" -Append
    }
}

Write-Host "`nForensic collection complete. Data saved to: $OutputDir"
