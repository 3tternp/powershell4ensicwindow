# ===============================
# Advanced Windows Forensics Script
# Author: ASTRA 3.0 
# Purpose: Collects extensive forensic artifacts
# ===============================

# Prep
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$OutputDir = "$env:USERPROFILE\Forensic_Dump_$timestamp"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
Write-Host "🔍 Collecting forensic artifacts to $OutputDir..."

# Function: Export registry keys
function Export-RegistryKey {
    param($Path, $OutFile)
    reg export $Path "$OutputDir\$OutFile" /y 2>$null
}

# System Info
systeminfo > "$OutputDir\SystemInfo.txt"
Get-ComputerInfo > "$OutputDir\ComputerInfo.txt"
hostname > "$OutputDir\Hostname.txt"
wmic bios get serialnumber > "$OutputDir\BIOSSerial.txt"

# Users and Sessions
net user > "$OutputDir\Users.txt"
quser > "$OutputDir\LoggedOnUsers.txt" 2>$null
query user >> "$OutputDir\LoggedOnUsers.txt" 2>$null
whoami /all > "$OutputDir\Whoami.txt"

# Process Tree
Get-Process | Sort-Object CPU -Descending | Out-File "$OutputDir\Processes.txt"

# Network Info
ipconfig /all > "$OutputDir\Network_Config.txt"
netstat -anob > "$OutputDir\Netstat_Full.txt"
Get-NetTCPConnection | Format-Table -AutoSize > "$OutputDir\TCPConnections.txt"
arp -a > "$OutputDir\ARP.txt"
net share > "$OutputDir\NetworkShares.txt"
route print > "$OutputDir\RouteTable.txt"

# USB History
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*' |
Select-Object FriendlyName, PSChildName |
Out-File "$OutputDir\USB_History.txt"

# Prefetch Files Listing
Get-ChildItem "$env:SystemRoot\Prefetch" -ErrorAction SilentlyContinue |
Select-Object Name, LastWriteTime |
Out-File "$OutputDir\PrefetchFiles.txt"

# Autoruns (basic)
Get-CimInstance -ClassName Win32_StartupCommand |
Select-Object Name, Command, User, Location |
Out-File "$OutputDir\Autoruns.txt"

# Services & Drivers
Get-Service | Where-Object {$_.Status -eq "Running"} | Out-File "$OutputDir\Services_Running.txt"
Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq "Running" } | 
Out-File "$OutputDir\Drivers.txt"

# Scheduled Tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State |
Out-File "$OutputDir\ScheduledTasks.txt"

# Installed Applications
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
Out-File "$OutputDir\InstalledApps.txt"

# Event Logs
$Since = (Get-Date).AddDays(-3)
$logLimit = 1000
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Since} -MaxEvents $logLimit |
Out-File "$OutputDir\SecurityEvents.txt"
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Since} -MaxEvents $logLimit |
Out-File "$OutputDir\SystemEvents.txt"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$Since} -MaxEvents $logLimit |
Out-File "$OutputDir\PowerShellLogs.txt"

# Registry Artifacts
Export-RegistryKey -Path "HKLM\SAM" -OutFile "SAM.reg"
Export-RegistryKey -Path "HKLM\SYSTEM" -OutFile "SYSTEM.reg"
Export-RegistryKey -Path "HKLM\SOFTWARE" -OutFile "SOFTWARE.reg"
Export-RegistryKey -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" -OutFile "UserRunKeys.reg"

# Browser History (Basic - Chrome)
$ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
if (Test-Path $ChromePath) {
    Copy-Item $ChromePath "$OutputDir\Chrome_History.db"
}

# Powershell History (if available)
$PSHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $PSHistory) {
    Copy-Item $PSHistory "$OutputDir\PS_History.txt"
}

# Hash critical executables
$criticalPaths = @(
    "$env:SystemRoot\System32\cmd.exe",
    "$env:SystemRoot\System32\powershell.exe",
    "$env:SystemRoot\explorer.exe",
    "$env:SystemRoot\System32\lsass.exe"
)

foreach ($file in $criticalPaths) {
    if (Test-Path $file) {
        Get-FileHash -Path $file -Algorithm SHA256 |
        Out-File "$OutputDir\Hash_CriticalBinaries.txt" -Append
    }
}

# Optionally compress output
$zipFile = "$OutputDir.zip"
Compress-Archive -Path $OutputDir -DestinationPath $zipFile -Force
Write-Host "✅ Forensic collection complete. Report saved to: $zipFile"
