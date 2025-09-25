# APP01 Network Services & Attack Surface — non-interactive, no prompts

$ErrorActionPreference = 'Stop'       # fail fast to avoid partial/interactive states
$ProgressPreference = 'SilentlyContinue'

Write-Host "== 1) Listening TCP ports mapped to processes =="
$procByPid = Get-CimInstance Win32_Process | Group-Object -Property ProcessId -AsHashTable -AsString  # process lookup
Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object {
  $p = $procByPid[[string]$_.OwningProcess]
  [pscustomobject]@{
    LocalAddress  = $_.LocalAddress
    LocalPort     = $_.LocalPort
    PID           = $_.OwningProcess
    ProcessName   = $p.Name
    ExecutablePath= $p.ExecutablePath
  }
}

Write-Host "`n== 2) DNS client configuration =="
Get-DnsClient | Select-Object InterfaceAlias,ConnectionSpecificSuffix,RegisterThisConnectionsAddress,UseSuffixWhenRegistering  # suffix/registration behavior
Get-DnsClientServerAddress | Select-Object InterfaceAlias,ServerAddresses                                                   # per-interface resolvers

Write-Host "`n== 3) IIS presence, version, and bindings =="
$webModuleAvailable = Get-Module -ListAvailable -Name WebAdministration
if ($webModuleAvailable) {
  Import-Module WebAdministration -ErrorAction Stop

  # IIS worker version (if present)
  if (Test-Path "$env:windir\system32\inetsrv\w3wp.exe") {
    Get-Item "$env:windir\system32\inetsrv\w3wp.exe" | Select-Object @{n='ProductVersion';e={$_.VersionInfo.ProductVersion}}, @{n='FileVersion';e={$_.VersionInfo.FileVersion}}  # IIS build
  } else {
    Write-Host "w3wp.exe not present (IIS worker not installed or not yet created)."
  }

  # Site inventory and bindings
  $sites = Get-Website
  if ($sites) {
    $sites | Select-Object Name,State,PhysicalPath,Bindings                                            # site list
    Get-WebBinding | Select-Object protocol,BindingInformation,hostHeader                              # binding details

    # Default documents and directory browsing — pass -Name explicitly (prevents prompts)
    Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/defaultDocument/files/add' -Name 'value' | Select-Object value  # default docs
    Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/directoryBrowse' -Name '.'                                      # dir browse settings

    # First site path and contents
    $sitePath = ($sites | Select-Object -First 1).PhysicalPath
    Write-Host "`nSitePath:" $sitePath
    if ($sitePath -and (Test-Path $sitePath)) {
      Get-ChildItem -Force -Path $sitePath | Select-Object Name,Length,LastWriteTime                  # web root inventory
    } else {
      Write-Host "Site path not found on disk."
    }
  } else {
    Write-Host "No IIS sites defined."
  }
} else {
  Write-Host "WebAdministration module not available; skipping IIS queries."
}

Write-Host "`n== 4) IIS bindings (redundant check for cross-reference) =="
if (Get-Module -Name WebAdministration) {
  Get-WebBinding | Select-Object protocol,BindingInformation,hostHeader
}

Write-Host "`n== 5) Completed APP01 network services & attack surface sweep =="
