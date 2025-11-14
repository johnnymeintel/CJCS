# show the 5 most recent Sysmon Process Create events (ID 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 5 |
  Format-List TimeCreated, Id, @{n='Message';e={$_.Message -replace "`r`n","\n"}}