# Executive workstation activity - focus on privileged actions
while ($true) {
    Clear-Host
    Write-Host "=== MGR1 WORKSTATION MONITOR ===" -ForegroundColor Cyan
    Write-Host "Time: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
    Write-Host "User: $env:USERNAME @ $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host ""
    
    # Check if Domain Admin is logged in
    Write-Host "Current User Groups:" -ForegroundColor Yellow
    whoami /groups | Select-String "Domain Admins|Administrators"
    
    # Recent process creation (potential attacks)
    Write-Host "`nRecent Processes (Last 5 min):" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        Id=1
        StartTime=(Get-Date).AddMinutes(-5)
    } -MaxEvents 10 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated,
            @{n='Process';e={$_.Properties[4].Value | Split-Path -Leaf}},
            @{n='CommandLine';e={
                $cmd = $_.Properties[10].Value
                if ($cmd.Length -gt 60) { $cmd.Substring(0,60) + "..." }
                else { $cmd }
            }} |
        Format-Table -AutoSize -Wrap
    
    Start-Sleep -Seconds 15
}