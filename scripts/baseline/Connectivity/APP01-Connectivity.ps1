# Verify connectivity to DC for authentication
Test-NetConnection -ComputerName dc01.cjcs.local -Port 88
Test-NetConnection -ComputerName dc01.cjcs.local -Port 389
Test-NetConnection -ComputerName dc01.cjcs.local -Port 53

# Check connectivity to SIEM for log forwarding
Test-NetConnection -ComputerName siem01.cjcs.local -Port 1514
Test-NetConnection -ComputerName siem01.cjcs.local -Port 1515

# Verify management connectivity from MGR1
Test-NetConnection -ComputerName win11-mgr1.cjcs.local -Port 3389 -InformationLevel Quiet

# Database and web service availability validation
netstat -an | findstr ":80\|:443\|:5432"
Get-Service | Where-Object {$_.Name -like "*iis*" -or $_.Name -like "*postgresql*"}

# Domain trust validation
Test-ComputerSecureChannel -Server DC01
nltest /sc_query:cjcs.local

# DNS resolution check
nslookup dc01.cjcs.local
nslookup win11-mgr1.cjcs.local
nslookup siem01.cjcs.local