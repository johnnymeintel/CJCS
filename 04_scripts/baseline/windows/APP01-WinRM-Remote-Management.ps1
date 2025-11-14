winrm enumerate winrm/config/listener # Lists WinRM listeners - detects unauthorized remote management endpoints and potential lateral movement vectors
winrm get winrm/config # Gets WinRM service configuration - baseline for remote management security settings and authentication requirements
Get-Item WSMan:\localhost\Service\Auth\* | Format-List # Gets WinRM authentication methods - monitors for weak auth configs that enable credential attacks
Get-NetFirewallRule -DisplayName '*WinRM*' | Select DisplayName,Enabled,Direction,Action,Profile # Gets WinRM firewall rules - validates remote access controls and network segmentation
Get-NetTCPConnection -LocalPort 5985 -State Listen | Select LocalAddress,LocalPort,State,OwningProcess # Confirms WinRM HTTP listener status - detects unauthorized remote management services
setspn -L $env:COMPUTERNAME # Lists computer SPNs including WinRM - validates Kerberos authentication setup and detects SPN hijacking