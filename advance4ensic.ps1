# ================================================
# Advanced Windows Forensic Collection Script
# Author: ASTRA 3.0
# Purpose: Gathers forensic artifacts for analysis
# ================================================

# Set up output directory
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$OutputDir = "$env:USERPROFILE\Forensic_Dump_$timestamp"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
Write-Host "Starting forensic data collection..."
Write-Host "Output directory: $OutputDir"

# Function to export registry keys
function Export-RegistryKey {
    param($Path, $OutFile)
    reg export $Path "$OutputDir\$OutFile" /y 2>$null
}

# Basic system info
systeminfo > "$OutputDir\SystemInfo.txt"
Get-ComputerInfo > "$OutputDir\ComputerInfo.txt"
hostname > "$OutputDir\Hostname.txt"
wmic bios get serialnumber > "$OutputDir\BIOSSerial.txt"

# User and session information
net user > "$OutputDir\Users.txt"
quser > "$OutputDir\LoggedOnUsers.txt" 2>$null
query user >> "$OutputDir\LoggedOnUsers.txt" 2>$null
whoami /all > "$OutputDir\Whoami.txt"

# Running processes
Get-Process | Sort-Object CPU -Descending | Out-File "$OutputDir\Processes.txt"

# Network configuration and activity
ipconfig /all > "$OutputDir\Network_Config.txt"
netstat -anob > "$OutputDir\Netstat_Full.txt"
Get-NetTCPConnection | Format-Table -AutoSize > "$OutputDir\TCPConnections.txt"
arp -a > "$OutputDir\ARP.txt"
net share > "$OutputDir\NetworkShares.txt"
route print > "$OutputDir\RouteTable.txt"

# USB history
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*' |
Select-Object FriendlyName, PSChildName |
Out-File "$OutputDir\USB_History.txt"

# Prefetch file listing
Get-ChildItem "$env:SystemRoot\Prefetch" -ErrorAction SilentlyContinue |
Select-Object Name, LastWriteTime |
Out-File "$OutputDir\PrefetchFiles.txt"

# Autorun programs
Get-CimInstance -ClassName Win32_StartupCommand |
Select-Object Name, Command, User, Location |
Out-File "$OutputDir\Autoruns.txt"

# Services and drivers
Get-Service | Where-Object {$_.Status -eq "Running"} | Out-File "$OutputDir\Services_Running.txt"
Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq "Running" } |
Out-File "$OutputDir\Drivers.txt"

# Scheduled tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State |
Out-File "$OutputDir\ScheduledTasks.txt"

# Installed applications
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
Out-File "$OutputDir\InstalledApps.txt"

# Recent Event Logs (last 3 days)
$Since = (Get-Date).AddDays(-3)
$logLimit = 1000

Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Since} -MaxEvents $logLimit |
Out-File "$OutputDir\SecurityEvents.txt"

Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Since} -MaxEvents $logLimit |
Out-File "$OutputDir\SystemEvents.txt"

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$Since} -MaxEvents $logLimit |
Out-File "$OutputDir\PowerShellLogs.txt"

# Export key registry hives
Export-RegistryKey -Path "HKLM\SAM" -OutFile "SAM.reg"
Export-RegistryKey -Path "HKLM\SYSTEM" -OutFile "SYSTEM.reg"
Export-RegistryKey -Path "HKLM\SOFTWARE" -OutFile "SOFTWARE.reg"
Export-RegistryKey -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" -OutFile "UserRunKeys.reg"

# Collect Chrome history file if it exists
$ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
if (Test-Path $ChromePath) {
    Copy-Item $ChromePath "$OutputDir\Chrome_History.db"
}

# PowerShell command history (if available)
$PSHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $PSHistory) {
    Copy-Item $PSHistory "$OutputDir\PS_History.txt"
}

# Hashes of critical executables
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

# Zip the output directory
$zipFile = "$OutputDir.zip"
Compress-Archive -Path $OutputDir -DestinationPath $zipFile -Force

Write-Host ""
Write-Host "Forensic data collection is complete."
Write-Host "Zipped report saved to: $zipFile"
