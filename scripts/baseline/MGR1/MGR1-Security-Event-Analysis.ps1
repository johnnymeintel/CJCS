Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 10 | Select-Object TimeCreated,Id,Message       # show last 10 logon (4624) and failed logon (4625) security events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 10 | Select-Object TimeCreated,Message               # show last 10 process creation (4688) events for new program executions
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3} -MaxEvents 5 | Select-Object TimeCreated,LevelDisplayName,Message # show last 5 system errors (level 2) and warnings (level 3)
