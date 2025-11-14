Get-ADForest | Select-Object Name,ForestMode,DomainNamingMaster,SchemaMaster # Gets AD forest info and FSMO roles - critical for domain trust monitoring
Get-ADDomain | Select-Object Name,DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster # Gets AD domain info and remaining FSMO roles - essential for AD health baseline
Get-Service ADWS,DNS,KDC,Netlogon,NTDS | Select-Object Name,Status,StartType # Checks critical AD service status - key indicators for domain controller health
repadmin /showrepl # Shows AD replication partners and status - identifies replication issues affecting security updates
repadmin /replsummary # Displays AD replication summary across all DCs - quick health check for domain sync
gpresult /r /scope computer # Shows applied computer group policies - validates security policy enforcement