# APP01 SMB Shares Access Assessment - Cookie Jar Cloud Solutions
# Fixed version that actually works instead of throwing ObjectNotFound errors

Write-Host "=== SMB Shares Configuration Baseline ===" -ForegroundColor Green

# Get all SMB shares first - this is your baseline inventory
Write-Host "`n[1] SMB Share Inventory:" -ForegroundColor Yellow
$shares = Get-SmbShare | Select-Object Name, Path, Description, ScopeName, ConcurrentUserLimit
$shares | Format-Table -AutoSize

# Get share access permissions for each discovered share (not hardcoded "ShareName")
Write-Host "`n[2] SMB Share Access Permissions:" -ForegroundColor Yellow
foreach ($share in $shares) {
    if ($share.Name -notin @('ADMIN$', 'C$', 'IPC$')) {  # Skip administrative shares
        Write-Host "  Share: $($share.Name)" -ForegroundColor Cyan
        try {
            Get-SmbShareAccess -Name $share.Name | Select-Object Name, AccountName, AccessControlType, AccessRight | Format-Table -AutoSize
        }
        catch {
            Write-Host "    ERROR: Cannot access permissions for $($share.Name)" -ForegroundColor Red
        }
    }
}

# Active SMB sessions - who's connected right now
Write-Host "`n[3] Active SMB Sessions:" -ForegroundColor Yellow
$sessions = Get-SmbSession | Select-Object ClientComputerName, UserName, NumOpens, SessionId
if ($sessions) {
    $sessions | Format-Table -AutoSize
} else {
    Write-Host "  No active SMB sessions found" -ForegroundColor Gray
}

# SMB server security configuration - the stuff that actually matters
Write-Host "`n[4] SMB Security Configuration:" -ForegroundColor Yellow
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EncryptData, RejectUnencryptedAccess, RequireSecuritySignature | Format-List

# Additional security checks that most people forget
Write-Host "`n[5] SMB Security Analysis:" -ForegroundColor Yellow
$config = Get-SmbServerConfiguration

# Check for the big security problems
if ($config.EnableSMB1Protocol) {
    Write-Host "  [CRITICAL] SMBv1 is enabled - this is 2025, not 2005" -ForegroundColor Red
}

if (-not $config.RequireSecuritySignature) {
    Write-Host "  [HIGH] Security signatures not required - relay attacks possible" -ForegroundColor Red
}

if (-not $config.EncryptData) {
    Write-Host "  [MEDIUM] SMB encryption disabled - data travels in cleartext" -ForegroundColor Yellow
}

if (-not $config.RejectUnencryptedAccess) {
    Write-Host "  [MEDIUM] Unencrypted access allowed - downgrade attacks possible" -ForegroundColor Yellow
}

# Open file handles - see what files are actually being accessed
Write-Host "`n[6] Open File Handles:" -ForegroundColor Yellow
$openFiles = Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path, ShareRelativePath
if ($openFiles) {
    $openFiles | Format-Table -AutoSize
} else {
    Write-Host "  No open file handles found" -ForegroundColor Gray
}

Write-Host "`n=== Assessment Complete ===" -ForegroundColor Green