Get-ComputerInfo | Select-Object WindowsProductName,OsBuildNumber,WindowsVersion,CsProcessors,CsDomain # Gets system baseline info - essential for asset inventory and configuration drift detection
Get-WmiObject Win32_ComputerSystem | Select-Object TotalPhysicalMemory # Gets physical memory info - baseline for system resource monitoring and anomaly detection
w32tm /query /status # Gets Windows time sync status - critical for accurate log timestamps and Kerberos authentication
w32tm /query /peers # Gets time sync peer sources - validates authorized time servers and detects rogue NTP configuration
ipconfig /all # Gets network configuration details - baseline for network interface monitoring and unauthorized network changes