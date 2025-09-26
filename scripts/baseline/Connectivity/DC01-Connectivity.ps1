# Basic network validation - DC to infrastructure systems
Test-NetConnection -ComputerName app01.cjcs.local -Port 80
Test-NetConnection -ComputerName app01.cjcs.local -Port 5432
Test-NetConnection -ComputerName win11-mgr1.cjcs.local -Port 3389
Test-NetConnection -ComputerName siem01.cjcs.local -Port 22

# DNS resolution validation - verify zone authority
nslookup app01.cjcs.local
nslookup win11-mgr1.cjcs.local  
nslookup siem01.cjcs.local
nslookup siem01

# Domain controller service verification
nltest /dclist:cjcs.local
w32tm /query /status
Get-Service ADWS,DNS,KDC,Netlogon | Format-Table Name,Status

# Active Directory health validation
repadmin /showrepl
dcdiag /test:dns /v

# Network services exposure validation
netstat -an | findstr ":53\|:88\|:389\|:636\|:3268"