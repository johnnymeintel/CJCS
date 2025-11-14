Get-ComputerInfo | Select-Object WindowsProductName,TotalPhysicalMemory,CsProcessors,CsDomain,CsWorkgroup   # OS name, total RAM, CPU count, and AD/workgroup membership
Test-ComputerSecureChannel -Verbose                                    # confirm AD Kerberos secure channel is healthy
$env:USERNAME; $env:USERDOMAIN                                         # current username and Windows domain
Get-NetIPAddress | Where-Object AddressFamily -eq "IPv4" | Select-Object IPAddress,InterfaceAlias   # list IPv4 addresses and network interfaces
whoami /groups                                                         # show all group memberships for current user
Get-NetAdapter | Select-Object Name,Status,LinkSpeed,MediaType         # network adapter names, link state, speed, and type