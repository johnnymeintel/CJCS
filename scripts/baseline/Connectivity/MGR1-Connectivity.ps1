# MGR1 Executive Workstation Connectivity Assessment
# Purpose: Validate executive access to critical business systems and domain services
# Context: Marcus Chen's daily driver workstation - needs authentication, app access, monitoring visibility

# Domain authentication connectivity - Kerberos ticket validation
Test-NetConnection dc01.cjcs.local -Port 88 -InformationLevel Quiet

# Business application access - InventoryFlow Pro web interface
Test-NetConnection app01.cjcs.local -Port 80 -InformationLevel Quiet

# Security monitoring access - SIEM management interface
Test-NetConnection siem01.cjcs.local -Port 22 -InformationLevel Quiet

# Domain trust relationship validation - verify workstation can authenticate to domain
Test-ComputerSecureChannel -Server DC01

# User context verification - confirm executive domain authentication
whoami /fqdn

# DNS resolution validation - verify name resolution for critical infrastructure
nslookup dc01.cjcs.local
nslookup app01.cjcs.local
nslookup siem01.cjcs.local