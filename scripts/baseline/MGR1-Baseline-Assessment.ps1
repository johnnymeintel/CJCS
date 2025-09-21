#!/usr/bin/env powershell
# MGR1 Executive Workstation Security Assessment - Cookie Jar Cloud Solutions
# Windows 11 endpoint security evaluation
# Author: Johnny Meintel
# Target: MGR1.cjcs.local (192.168.100.101)

"==============================================================================="
"MGR1 SECURITY ASSESSMENT - COOKIE JAR CLOUD SOLUTIONS"
"Target: $env:COMPUTERNAME.$env:USERDNSDOMAIN ($(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne '127.0.0.1'} | Select-Object -First 1 -ExpandProperty IPAddress))"
"Assessment Start: $(Get-Date)"
"==============================================================================="

# System Information
"`n=== SYSTEM IDENTIFICATION ==="
Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,TotalPhysicalMemory,CsProcessors,CsDomain

"`n=== DOMAIN STATUS ==="
Test-ComputerSecureChannel
"Current User: $env:USERDOMAIN\$env:USERNAME"

"`n=== USER PRIVILEGES ==="
whoami /priv | Select-String -Pattern "(SeDebug|SeBackup|SeRestore|SeTakeOwnership)"

"`n=== LOCAL ADMINISTRATORS ==="
Get-LocalGroupMember "Administrators" | Select-Object Name,PrincipalSource

"`n=== CACHED CREDENTIALS ==="
klist
$CachedLogons = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue
"Cached Logon Count: $($CachedLogons.CachedLogonsCount)"

"`n=== ENDPOINT PROTECTION ==="
Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated

"`n=== LSA PROTECTION ==="
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue

"`n=== NETWORK SERVICES ==="
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort

"`n=== RDP CONFIGURATION ==="
$RDPSetting = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
"RDP Enabled: $($RDPSetting.fDenyTSConnections -eq 0)"

"`n=== FIREWALL STATUS ==="
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction

"`n=== BITLOCKER STATUS ==="
Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus

"`n=== STARTUP PROGRAMS ==="
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location

"`n=== RECENT PATCHES ==="
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledOn | Select-Object -First 5

"`n=== AUTORUN ENTRIES ==="
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue

"`n=== DOMAIN CONNECTIVITY ==="
Test-NetConnection dc01.cjcs.local -Port 389 | Select-Object ComputerName,RemotePort,TcpTestSucceeded
Test-NetConnection dc01.cjcs.local -Port 445 | Select-Object ComputerName,RemotePort,TcpTestSucceeded

"==============================================================================="
"ASSESSMENT COMPLETE: $(Get-Date)"
"==============================================================================="