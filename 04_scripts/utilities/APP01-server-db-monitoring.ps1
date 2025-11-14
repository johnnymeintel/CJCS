# Combined IIS + PostgreSQL + Security monitor
while ($true) {
    Clear-Host
    Write-Host "=== APP01 APPLICATION MONITOR ===" -ForegroundColor Cyan
    Write-Host "Time: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    # Check PostgreSQL service
    Write-Host "PostgreSQL Status:" -ForegroundColor Yellow
    Get-Service postgresql-x64-17 | Select-Object Status, StartType
    
    # Recent Security events
    Write-Host "`nSecurity Events (Last 5 min):" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{
        LogName='Security'
        StartTime=(Get-Date).AddMinutes(-5)
    } -MaxEvents 10 -ErrorAction SilentlyContinue |
        Group-Object Id | Select-Object Count, Name |
        Format-Table -AutoSize
    
    # Recent Sysmon process creations
    Write-Host "Process Creations (Last 5 min):" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        Id=1
        StartTime=(Get-Date).AddMinutes(-5)
    } -MaxEvents 5 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated,
            @{n='Process';e={$_.Properties[4].Value | Split-Path -Leaf}} |
        Format-Table -AutoSize
    
    Start-Sleep -Seconds 15
}