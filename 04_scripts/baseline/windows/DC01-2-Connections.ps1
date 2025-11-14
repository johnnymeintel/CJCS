# What's DC01 talking to RIGHT NOW?
Get-NetTCPConnection -State Established | 
  Where-Object {$_.RemoteAddress -ne "::1" -and $_.RemoteAddress -ne "127.0.0.1"} |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).Name}} |
  Format-Table -AutoSize