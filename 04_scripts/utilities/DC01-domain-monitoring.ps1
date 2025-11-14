# PowerShell monitoring loop - authentication events
while ($true) {
    Clear-Host
    Write-Host "=== DC01 AUTHENTICATION MONITOR ===" -ForegroundColor Cyan
    Write-Host "Time: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    # Failed logons (last 5 minutes)
    Write-Host "FAILED LOGONS (Last 5 min):" -ForegroundColor Red
    Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4625
        StartTime=(Get-Date).AddMinutes(-5)
    } -ErrorAction SilentlyContinue | 
        Select-Object -First 5 TimeCreated, 
            @{n='User';e={$_.Properties[5].Value}},
            @{n='Source';e={$_.Properties[19].Value}} |
        Format-Table -AutoSize
    
    # Successful logons (last 5 minutes)
    Write-Host "SUCCESSFUL LOGONS (Last 5 min):" -ForegroundColor Green
    Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4624
        StartTime=(Get-Date).AddMinutes(-5)
    } -ErrorAction SilentlyContinue |
        Where-Object {$_.Properties[8].Value -in @(2,3,10)} |  # Interactive, Network, RDP
        Select-Object -First 5 TimeCreated,
            @{n='User';e={$_.Properties[5].Value}},
            @{n='Type';e={$_.Properties[8].Value}},
            @{n='Source';e={$_.Properties[18].Value}} |
        Format-Table -AutoSize
    
    Start-Sleep -Seconds 10
}