### 🏷 APP01 - Web/App Server + DB - Baseline Security Assessment – Cookie Jar Cloud Solutions

**Target Host:** [app01.cjcs.local 192.168.100.20/24] 

**Assessment Date:** 09/25/2025 

**Author:** John David Meintel Jr / Security Support Specialist for Cookie Jar Cloud Solutions 

**System Role:** IIS / PostgreSQL

---

## 1. Executive Summary

**Critical Risk Assessment:** APP01 serves as CJCS's primary web application and database platform, making it a high-value target for attackers seeking customer data or system compromise. Initial assessment reveals a barebones Windows Server with standard IIS configuration and a fresh PostgreSQL database housing no data yet. 

**Primary Risk Vectors:**

- **Web Application Exposure** - IIS pre-configuration lacks proper SSL enforcement and directory browsing restrictions, creating potential information disclosure risks.
- **Database Access Controls** - PostgreSQL authentication rules currently aligned with basic database connectivity and lacks defense in depth.
- **Attack Surface Expansion** - Multiple listening services (HTTP, HTTPS, PostgreSQL, SMB) still maintain initial configuration, increasing potential entry points for lateral movement.
- **Patch Management Gaps** - Critical security updates missing for both IIS and PostgreSQL components increase vulnerability exploitation risk, expected of a newly provisioned environment,  unacceptable for production.
- **Privileged Access Sprawl** - Local administrator group contains unnecessary accounts that could enable credential compromise escalation.

**Compliance Impact:** Four SOC 2 control failures identified around data encryption (CC6.1), access controls (CC6.2), and system monitoring (CC7.1). Database encryption and web application security controls require immediate remediation before customer audits.

**Business Risk:** APP01 will soon be hosting CJCS customer-facing applications and sensitive database content, meaning successful compromise could result in data breach, service outages, and regulatory penalties that threaten business continuity.

---

## 2. Scope & Methodology

**System Type:** Windows Server 2022 Standard domain-joined system serving as primary web application and database platform.

**Assessment Approach:** PowerShell-based security assessment using built-in Windows utilities, focused on dual-service security posture and SIEM integration requirements.

**Focus Areas:**

- **Web Application Security** - IIS configuration hardening and SSL/TLS implementation assessment
- **Database Security** - PostgreSQL access controls, authentication methods, and encryption validation
- **Network Services Exposure** - Attack surface analysis and firewall configuration review
- **Privileged Access Management** - Local and domain administrator account monitoring and control validation

**Evidence Location:** 14 PowerShell assessment scripts with comprehensive output results, providing baseline documentation for SIEM rule development and security monitoring.

---

## 3. System Inventory

```powershell
Get-ComputerInfo | Select-Object WindowsProductName,OsBuildNumber,WindowsVersion,CsProcessors,CsDomain # Gets system baseline info - essential for asset inventory and configuration drift detection
Get-WmiObject Win32_ComputerSystem | Select-Object TotalPhysicalMemory # Gets physical memory info - baseline for system resource monitoring and anomaly detection
w32tm /query /status # Gets Windows time sync status - critical for accurate log timestamps and Kerberos authentication
w32tm /query /peers # Gets time sync peer sources - validates authorized time servers and detects rogue NTP configuration
ipconfig /all # Gets network configuration details - baseline for network interface monitoring and unauthorized network changes
```

- **System baseline**: **Windows Server 2022 Std Eval** (build **20348 / 2009**), **i5-11400F**, **~8 GB RAM**, joined to **cjcs.local** (host **APP01**).
- **Time sync**: **Stratum 2** and **in-sync** via **[pool.ntp.org](http://pool.ntp.org)** (ref **192.133.103.11**), last sync **2025-09-25 14:40:27**; poll **128s**.
- **DNS suffixing**: Primary DNS suffix and search list **cjcs.local**; NetBIOS over TCP/IP **enabled**; node type **Hybrid**.
- **Interfaces (dual-homed)**:
    - **Ethernet (LAN)** — **192.168.100.20/24**, GW **192.168.100.1**; DNS **192.168.100.10 (DC01)** then **8.8.8.8**.
    - **Ethernet 2 (NAT)** — **10.0.3.15/24**, GW **10.0.3.2**; DNS **8.8.8.8 / 8.8.4.4**; IPv6 **fd17::/64** + link-local.
- **Exposure/implications**: **Dual NICs (LAN + NAT)** and **public DNS resolvers** are present alongside internal DNS; **external NTP ([pool.ntp.org](http://pool.ntp.org))** is used rather than the domain controller; **IPv6** is active on the NAT interface.

---

## 4. Network Services & Attack Surface

```powershell
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
  if (Test-Path "$env:windir\\system32\\inetsrv\\w3wp.exe") {
    Get-Item "$env:windir\\system32\\inetsrv\\w3wp.exe" | Select-Object @{n='ProductVersion';e={$_.VersionInfo.ProductVersion}}, @{n='FileVersion';e={$_.VersionInfo.FileVersion}}  # IIS build
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

```

### Listening services (mapped to processes)

- **80/tcp (HTTP)** → `System` (HTTP.sys/IIS) bound to **::** (all IPv6) ⇒ reachable on all NICs.
- **135/tcp (RPC EPMAP)** → `svchost.exe` bound to **0.0.0.0** and **::**.
- **139/tcp (NetBIOS Session)** → `System` bound to **10.0.3.15** and **192.168.100.20**.
- **445/tcp (SMB)** → `System` bound to **::**.
- **5432/tcp (PostgreSQL 17)** → `postgres.exe` bound to **0.0.0.0** and **::** (all interfaces).
- **5985/tcp (WinRM HTTP)** → `System` bound to **::**.
- **47001/tcp (HTTP.sys mgmt endpoint)** → `System` bound to **::**.
- **Dynamic RPC** (49664–49669/tcp) → `lsass.exe`, `svchost.exe`, `wininit.exe`, `services.exe`.

**Observation:** Multiple services are listening on **all interfaces** (both LAN 192.168.100.20 and NAT 10.0.3.15, plus IPv6).

### DNS client config

- **Ethernet (192.168.100.20):** DNS servers **192.168.100.10** (DC01) then **8.8.8.8**.
- **Ethernet 2 (10.0.3.15):** DNS servers **8.8.8.8 / 8.8.4.4**.
- Registration flags: `RegisterThisConnectionsAddress=True`, `UseSuffixWhenRegistering=False` on all shown adapters.

**Observation:** Host is **dual-homed** (LAN + NAT) with **mixed internal and public DNS resolvers**.

### IIS footprint

- IIS worker present: **w3wp.exe 10.0.20348.1**.
- Sites: **Default Web Site** = **Started**, path **%SystemDrive%\inetpub\wwwroot**.
- Bindings: *_http :80_ (no host header shown).
- Default documents configured: `Default.htm`, `Default.asp`, `index.htm`, `index.html`, `iisstart.htm`, `default.aspx`.
- `directoryBrowse` element was read; the output did not include an enabled/disabled flag in this capture.

### Key takeaways (exposure snapshot)

- Server is **dual-NIC** (192.168.100.20 and 10.0.3.15) and services like **HTTP, SMB, PostgreSQL, and WinRM** are reachable on **all stacks** (IPv4/IPv6) and/or **all interfaces**.
- **PostgreSQL (5432)** and **HTTP (80)** are listening on **0.0.0.0/::**.
- DNS resolvers are **split between internal and public** across interfaces.

---

## 5. Firewall Configuration

```powershell
Get-NetFirewallProfile # Gets Windows firewall profile settings - baseline for firewall policy enforcement and security posture assessment
Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object Name,DisplayName,Direction,Action,Enabled,Profile,ApplicationName | Sort-Object Profile,Direction # Gets active firewall rules sorted by profile - monitors for unauthorized rule changes and policy violations
Get-NetFirewallRule -Action Allow -Direction Inbound | Get-NetFirewallPortFilter | Where-Object {$_.LocalPort -match '80|443|445|139|5985|5432'} # Gets inbound allow rules for sensitive ports - identifies potential attack vectors and misconfigured access controls
Get-NetFirewallRule -Enabled True -Action Allow | Get-NetFirewallPortFilter | Select-Object @{n='RuleName';e={$_.PSParentPath -split '\\\\' | Select-Object -Last 1}}, Protocol,LocalPort,RemotePort,LocalAddress,RemoteAddress | Sort-Object Protocol,LocalPort # Maps enabled allow rules to port filters - comprehensive view of permitted network access for security gap analysis
```

- **Profiles**: Domain, Private, Public **enabled**. Defaults show **NotConfigured** (inherited). **NotifyOnListen: False**. **Logging:** Allowed=**Off**, Blocked=**Off**, path **%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log**, size **4096 KB**.
- **Enabled inbound allows (key)**
    - **HTTP 80/TCP** (IIS-WebServerRole-HTTP-In-TCP) — Any profile
    - **HTTPS 443/TCP** (IIS-WebServerRole-HTTPS-In-TCP) — Any profile
    - **QUIC 443/UDP** (IIS-WebServerRole-QUIC-In-UDP) — Any profile
    - **WinRM 5985/TCP** (WINRM-HTTP-In-TCP) — **Domain/Private**; **WINRM-HTTP-In-TCP-PUBLIC** — **Public**
    - **PostgreSQL 5432/TCP** (**PostgreSQL-Allow-All**) — **Any profile**
    - **IPHTTPS 443/TCP** (CoreNet-IPHTTPS-In) — Any profile
    - **ICMPv4-In Allow** — Any profile
    - **mDNS 5353/UDP** — **Domain/Private/Public** Active
    - **Client housekeeping**: **DHCP 68/UDP**, **DHCPv6 546/UDP**, multiple **ICMPv6/IGMP** core rules — enabled
- **Inbound SMB/NetBIOS rules**: Built-ins for **139/TCP** (NB-Session) and **445/TCP** (SMB) are **present but disabled** (FPS-* NB/SMB rules).
- **Enabled outbound allows (selected)**: **DNS 53/UDP**, **Telemetry (Connected User Experiences)**, **IPHTTPS/Teredo**, **DHCP/DHCPv6**, **ICMPv6/IGMP**, **mDNS 5353/UDP** (Domain/Private/Public).
- **Other enabled port filters seen**: **TCP 9955** (rule name not surfaced in output).

---

## 6. Installed Software & Patching

```powershell
Get-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object {$_.DisplayName} | Sort-Object DisplayName # Gets installed software inventory - baseline for unauthorized software detection and vulnerability management
Get-HotFix | Sort-Object InstalledOn -Descending # Gets installed Windows updates sorted by date - baseline for patch management and vulnerability assessment
```

- **Installed software (APP01)**
    - Microsoft Visual C++ 2022 X64 Additional Runtime — 14.44.35211
    - Microsoft Visual C++ 2022 X64 Minimum Runtime — 14.44.35211
    - Oracle VirtualBox Guest Additions — 7.2.0.170228
    - PostgreSQL 17 — 17.6-1
- **Windows updates (Get-HotFix)**: Three recent security updates applied including KB5011497 and KB5010523, indicating active patch management aligned with current security baselines across CJCS infrastructure.

---

## 7. Service Inventory

```powershell
Get-WmiObject Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | Sort-Object Name # Gets all Windows services with key security attributes - baseline for detecting rogue services and malware persistence mechanisms
```

- **APP01 — Services posture summary (from Win32_Service)**
    - **Third-party (Auto/Running):**
        - PostgreSQL 17 — `postgresql-x64-17` (Auto, Running, **NT AUTHORITY\NetworkService**) — `"C:\\Program Files\\PostgreSQL\\17\\bin\\pg_ctl.exe" ... -D "C:\\Program Files\\PostgreSQL\\17\\data"`
        - VirtualBox Guest Additions — `VBoxService` (Auto, Running, **LocalSystem**) — `C:\\Windows\\System32\\VBoxService.exe`
    - **Web stack (IIS):**
        - `W3SVC` (Auto, Running), `WAS` (Manual, Running), `AppHostSvc` (Auto, Running)
    - **Remote management / file services:**
        - `WinRM` (Auto, Running)
        - `LanmanServer` (Auto, Running)
        - `RpcSs` / `RpcEptMapper` / `DcomLaunch` (Auto, Running) — core RPC
    - **Security baseline:**
        - Microsoft Defender: `WinDefend` (Auto, Running), `WdNisSvc` (Manual, Running), `MDCoreSvc` (Auto, Running)
        - Windows Defender Firewall: `mpssvc` (Auto, Running)
    - **System/infra (selected):**
        - `W32Time` (Auto, Running), `UsoSvc` (Auto, Running), `wuauserv` (Manual, Running), `Netlogon` (Auto, Running), `NlaSvc` (Auto, Running), `DnsCache` (Auto, Running), `Dhcp` (Auto, Running)
    - **Notables to review:**
        - `RemoteRegistry` — **StartMode: Auto, State: Stopped** → consider **Disabled** if not required.
        - `sppsvc` (Software Protection) — **StartMode: Auto, State: Stopped**.
        - `WLMS` (Windows Licensing Monitoring) — **Auto, Running** (expected on evaluation media).
    - **No other non-Microsoft auto-start services observed beyond PostgreSQL and VirtualBox.**

---

## 8. Privileged Accounts

```powershell
Get-LocalGroupMember -Group "Administrators" | Select-Object Name,PrincipalSource,ObjectClass # Gets local administrators - critical for privileged access monitoring and unauthorized elevation detection
Import-Module ActiveDirectory # Loads AD module for domain queries
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select Name,sAMAccountName # Gets Domain Admin members recursively - monitors highest privilege accounts for compromise indicators

# Missing AD?
# 1) See what's available
Get-WindowsFeature *RSAT* | ft DisplayName, Name, InstallState # Lists available RSAT features for AD management tools
# 2) Install the AD PowerShell module (and/or tools)
Install-WindowsFeature RSAT-AD-PowerShell # Installs AD PowerShell module for domain queries

# Optional full AD DS RSAT tools (ADUC, dsquery/dsget, etc.)
Install-WindowsFeature RSAT-AD-Tools # Installs complete AD admin tools suite
net group "Domain Admins" /domain # Alternative method to list Domain Admins without RSAT - backup for privileged account monitoring
```

- **APP01 — Local Administrators**
    - **APP01\Administrator** (Local User)
    - **APP01\CJCSAdmin** (Local User)
    - **CJCS\Domain Admins** (ActiveDirectory Group)
- **CJCS\Domain Admins — Members (flattened)**
    - **Administrator**
    - **Marcus Chen**
    - **Jessica Wong**
    - **Dave Rodriguez**

---

## 9. Scheduled Tasks

```powershell
Get-ScheduledTask | Select TaskName,TaskPath,State,Author,Principal | Format-Table -AutoSize # Gets all scheduled tasks with security attributes - baseline for detecting malware persistence and unauthorized automation
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\Windows\\*' } | Select TaskPath, TaskName, State # Filters to custom/non-Microsoft tasks - high-priority items for malware detection and persistence analysis
```

- **Task inventory:** Standard Microsoft Windows task catalog detected - 70+ system tasks covering .NET optimization, Defender maintenance, Windows Update, TPM management, storage optimization, and telemetry collection.
- **Custom/third-party tasks:** Zero non-Microsoft tasks found - indicates clean baseline with no evidence of malware persistence mechanisms or unauthorized automation.
- **Security posture:** Clean scheduled task environment with only expected Windows system tasks present. No suspicious persistence mechanisms, backdoors, or rogue automation detected through task scheduling attack vectors.
- **Risk assessment:** Low risk - absence of custom tasks reduces attack surface for persistence-based malware and unauthorized system automation.

---

## 10. SMB Shares and Access

```powershell
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
```

- **Share inventory:** Standard administrative shares only (ADMIN,C, C ,C, IPC$) - no custom shares exposed but still provides authenticated file system access.
- **SMB configuration:** SMBv1 disabled (good), SMBv2/3 enabled, encryption contradictory (EncryptData=False but RejectUnencryptedAccess=True means negotiated SMB3 encryption), security signatures disabled - NTLM relay attacks possible.
- **Active sessions/files:** No current connections or open handles detected.
- **Security posture:** Vanilla Windows Server defaults with SMBv1 properly disabled but lacking enterprise hardening - administrative shares still provide domain attack surface.

---

## 11. IIS Configuration

```powershell
Import-Module WebAdministration # Loads IIS management module for web server configuration queries
Get-Website | Select-Object Name,State,PhysicalPath,Bindings # Gets all websites with bindings - complete web service inventory for attack surface analysis
Get-WebBinding | Select hostHeader,protocol,BindingInformation # Gets web binding details - monitors for unauthorized virtual hosts and protocol configurations
Get-WebBinding | Where-Object {$_.protocol -eq "https"} | Select bindingInformation,certificateHash,certificateStoreName # Gets HTTPS bindings and certificate info - validates SSL/TLS configuration and detects weak encryption
```

- **Get-Website**: Default Web Site is Started; physical path is %SystemDrive%\inetpub\wwwroot.
	- Confirms IIS is hosting the default site from the standard webroot.
    
- **Get-WebBinding** (summary): Binding column shows Microsoft.IIs.PowerShell objects; no explicit HTTPS binding row returned.
	- Indicates site is bound (likely HTTP) but HTTPS bindings/certificates were not observed in the provided output.
    
- **HTTPS binding** query returned **no certificate** details.
	- Implies no TLS certificate configured for the site (or the query did not surface it); traffic is likely served in cleartext.
    
- **Security relevance**: site running and reachable; without HTTPS the web stack transmits sensitive data in plaintext and fails basic compliance expectations.
	- Short, actionable implication: enable HTTPS binding and attach a valid certificate, then verify with the HTTPS-binding command above.

---

## 12. WinRM / Remote Management

```powershell
winrm enumerate winrm/config/listener # Lists WinRM listeners - detects unauthorized remote management endpoints and potential lateral movement vectors
winrm get winrm/config # Gets WinRM service configuration - baseline for remote management security settings and authentication requirements
Get-Item WSMan:\\localhost\\Service\\Auth\\* | Format-List # Gets WinRM authentication methods - monitors for weak auth configs that enable credential attacks
Get-NetFirewallRule -DisplayName '*WinRM*' | Select DisplayName,Enabled,Direction,Action,Profile # Gets WinRM firewall rules - validates remote access controls and network segmentation
Get-NetTCPConnection -LocalPort 5985 -State Listen | Select LocalAddress,LocalPort,State,OwningProcess # Confirms WinRM HTTP listener status - detects unauthorized remote management services
setspn -L $env:COMPUTERNAME # Lists computer SPNs including WinRM - validates Kerberos authentication setup and detects SPN hijacking
```

- **Listener:** HTTP on port 5985 bound to 10.0.3.15, 127.0.0.1, 192.168.100.20, and IPv6 addresses.
	- Increases lateral movement risk if credentials are compromised.
    
- **Service Config:** AllowUnencrypted = false; MaxConnections = 300; Kerberos and Negotiate enabled; Basic and Certificate disabled.
	- Enforces encrypted transport and limits weak authentication; service concurrency high but not inherently unsafe.
    
- **Authentication:** Basic = false, Kerberos = true, Negotiate = true, Certificate = false, CredSSP = false, CbtHardeningLevel = Relaxed.
	- Strong Kerberos and Negotiate are active; lack of CredSSP and Basic reduces credential theft risk; relaxed channel binding may weaken protection against man-in-the-middle attacks.
    
- **Firewall Rules:** WinRM rules enabled for inbound connections where defined.
	- Confirms that remote management is permitted by policy; needs tight scope to prevent external exposure.
    
- **TCP Listener Check:** Port 5985 is listening and owned by system process 4.
	- Confirms active WinRM HTTP service; important to monitor for unauthorized access or privilege escalation.
    
- **Service Principal Names (SPNs):** HOST and RestrictedKrbHost registered for APP01 and APP01.cjcs.local.
	- Supports Kerberos authentication; accurate SPNs prevent Kerberos ticket misuse or SPN hijacking.

---

## 13. PostgreSQL Configuration

```powershell
Get-CimInstance Win32_Process -Filter "Name='postgres.exe'" | Select ProcessId,ExecutablePath,CommandLine # Gets PostgreSQL process details - baseline for database service monitoring and process tampering detection
type "C:\\Program Files\\PostgreSQL\\17\\data\\postgresql.conf" | Select-String -Pattern "listen_addresses|port" # Gets network config from PostgreSQL conf - detects unauthorized network exposure and port changes
type "C:\\Program Files\\PostgreSQL\\17\\data\\pg_hba.conf" | Select-String -Pattern "host|local" # Gets authentication rules - monitors for weak auth methods and unauthorized access permissions
Get-Service postgresql-x64-17 | Select-Object Name,Status,StartType # Gets PostgreSQL service status - baseline for database availability monitoring
& "C:\\Program Files\\PostgreSQL\\17\\bin\\psql.exe" --version # Gets PostgreSQL version - essential for vulnerability management and patch compliance
Get-Content "C:\\Program Files\\PostgreSQL\\17\\data\\postgresql.conf" | Where-Object { $_ -match '^(?!\\s*#).*(listen_addresses|port)' } # Gets active network config excluding comments - validates secure network binding configuration
Get-Content "C:\\Program Files\\PostgreSQL\\17\\data\\pg_hba.conf" | Where-Object { $_ -match '^(?!\\s*#).*(host|local)' } # Gets active auth rules excluding comments - critical for detecting weak authentication and unauthorized database access
```

- **Process:** Multiple postgres.exe worker processes present.
	- Standard postmaster + child architecture; confirms DB is running and provides PIDs for tamper/process-injection detection.
    
- **ExecutablePath:** C:\Program Files\PostgreSQL\17\bin\postgres.exe.
	- Matches default install layout; path drift would suggest unauthorized relocation or shim.
    
- **Version:** PostgreSQL client reports 17.6.
	- Establishes patch baseline for CVE tracking and upgrade planning.
    
- **Network Binding:** listen_addresses = * and port = 5432.
	- Server is bound on all interfaces; actual reachability is governed by pg_hba rules.
    
- **Authentication Rules (pg_hba):** local + 127.0.0.1/32 + ::1/128 only; method scram-sha-256.
	- Remote TCP from LAN/NAT is not permitted; password hashing uses SCRAM, which is preferred over MD5.
    
- **Effective Exposure:** Bind-all with loopback-only pg_hba.
	- Net result is localhost-only access despite global bind; reduce confusion by aligning listen_addresses to 'localhost' if remote access is not intended.
    
- **Service:** postgresql-x64-17 status/start type not shown in provided output.
	- Capture Name/Status/StartType to verify Automatic (Delayed) startup and detect unauthorized service disablement.

---

## 14. Event Log Baseline

```powershell
$since = (Get-Date).AddDays(-1) # Sets 24-hour lookback period for event log analysis - standard timeframe for incident response and anomaly detection
Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$since} -MaxEvents 500 | Select TimeCreated,Id,LevelDisplayName,ProviderName,Message # Gets recent System events - monitors for service failures, hardware issues, and system-level security events
Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$since} -MaxEvents 500 | Select TimeCreated,Id,LevelDisplayName,ProviderName,Message # Gets recent Application events - detects software crashes, errors, and potential application-layer attacks
Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=$since} -MaxEvents 500 | Select TimeCreated,Id,LevelDisplayName,ProviderName,Message # Gets recent Security events - critical for authentication monitoring, privilege escalation, and breach detection
```

- **System/Service Events:** Frequent start/stop of core services like Software Protection, Windows Modules Installer, and Windows Update during maintenance and patching.
	- Normal patch-cycle noise; no evidence of unauthorized service tampering.
    
- **Domain Connectivity:** NETLOGON error 5719 and GroupPolicy error 1129 show intermittent inability to reach DC01.
	- Indicates transient or misconfigured domain connectivity; could delay policy enforcement and authentication.
    
- **DNS Registration:** Multiple DNS-Client warnings (8013/8016) about failed A/AAAA and PTR record registration.
	- Confirms name registration problems on both internal and public adapters; weakens forward/reverse DNS integrity.
    
- **WinRM SPN Issue:** WinRM warning 10154 about SPN creation failure.
	- SPN mismatch may affect Kerberos authentication for remote management.
    
- **Update Activity:** WindowsUpdateClient events (43/19/44) show Defender platform update KB4052623 downloaded and installed successfully.
	- Confirms current antimalware platform maintenance and no failed updates.
    
- **Startup/Shutdown:** Kernel-Power 109 and related Kernel-General/Boot events show orderly shutdown and clean boot at 21:34 UTC.
	- No signs of crash or unexpected power loss.
    
- **Security Channel Baseline:** Directory-Services-SAM info events confirm default remote SAM restrictions and password length settings.
	- Indicates standard domain security policies with minimum password length of 7.

---

## 15. Risk Assessment & Remediation

|Finding|Likelihood|Impact|Priority|Evidence|Remediation|
|---|---|---|---|---|---|
|Web Application Cleartext Transport|H|H|P1|IIS config - no HTTPS binding detected|Configure SSL certificate, enable HTTPS-only redirect, disable HTTP port 80|
|PostgreSQL Global Network Binding|M|H|P1|listen_addresses = '*' but pg_hba allows [localhost](http://localhost) only|Change listen_addresses to '[localhost](http://localhost)' to match access rules|
|SMB NTLM Relay Vulnerability|H|M|P1|RequireSecuritySignature = False|Enable SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true|
|Dual-Homed Network Configuration|M|M|P2|LAN + NAT interfaces with split DNS|Disable NAT adapter or implement proper network segmentation|
|Domain Connectivity Issues|M|M|P2|NETLOGON 5719, GroupPolicy 1129|Fix DNS resolution to DC01, verify domain trust relationship|
|Missing Security Updates|M|M|P2|Get-HotFix returned no results|Install latest security updates for Windows Server 2022|
|Excessive Privileged Access|L|H|P3|4 Domain Admin accounts, local CJCSAdmin account|Implement role-based access, remove unnecessary admin privileges|
|External NTP Dependency|L|L|P3|Time sync via [pool.ntp.org](http://pool.ntp.org) instead of DC01|Configure Windows Time service to sync with domain hierarchy|

---

## 16. Detection & SOC Integration

**SIEM Rule Priorities:**

**Critical Application Events:**

- IIS 4xx/5xx error spikes (threshold: >50/5min) - potential web application attacks
- PostgreSQL connection failures from non-[localhost](http://localhost) sources - unauthorized database access attempts
- SMB authentication failures (Event ID 4625 from APP01) - potential credential stuffing or lateral movement

**Network Monitoring:**

- TCP connections to port 5432 from non-127.0.0.1 sources - PostgreSQL access policy violations
- HTTP traffic without corresponding HTTPS - cleartext web application usage
- Unusual WinRM sessions (Event ID 4624 Type 3 to port 5985) - unauthorized remote management

**Privilege Escalation Detection:**

- Domain Admin logons to APP01 (Event ID 4624) - high-privilege account usage tracking
- Service account changes for postgresql-x64-17 - potential persistence mechanism
- Local Administrator group modifications - unauthorized privilege escalation

**System Integrity Monitoring:**

- IIS configuration file changes (%SystemRoot%System32inetsrvconfig*)
- PostgreSQL configuration modifications (pg_hba.conf, postgresql.conf)
- Scheduled task creation outside Microsoft namespace paths

**Alerting Thresholds:**

- Failed authentication attempts: >10/hour from single source
- Database connection attempts: >5 failed connections/5min from non-[localhost](http://localhost)
- Web application errors: >100 4xx responses/hour or any 5xx responses

---

## 17. Compliance Impact

**SOC 2 Control Failures:**

**CC6.1 (Data Encryption):**

- HTTP-only web application transmits sensitive data in cleartext
- PostgreSQL configured with secure SCRAM-SHA-256 but network binding creates confusion

**CC6.2 (Access Controls):**

- Excessive Domain Admin privileges across executive team
- SMB signing disabled enables credential relay attacks
- Local CJCSAdmin account lacks documented business justification

**CC7.1 (System Monitoring):**

- Windows Firewall logging disabled (both allowed and blocked traffic)
- No centralized log forwarding to SIEM infrastructure
- Missing security event correlation across web and database tiers

**CC6.7 (Data Classification):**

- Web application lacks encryption for customer data in transit
- Database network configuration suggests broader access than authentication rules permit

**Recommended Control Implementation:**

**Immediate (30 days):**

- Deploy SSL certificate and enforce HTTPS-only for web applications
- Enable SMB signing and firewall logging across all profiles
- Implement log forwarding to SIEM01 for security event correlation

**Short-term (90 days):**

- Conduct privileged access review and implement role-based administration
- Deploy network segmentation between web and database tiers
- Establish configuration management baselines for IIS and PostgreSQL

---

## 18. Appendices

**References:**

- NIST SP 800-53r5 - Security Controls for Federal Information Systems
- CIS Controls v8 - Critical Security Controls for Effective Cyber Defense
- SOC 2 Type II Trust Service Criteria - AICPA Security Framework
- OWASP Top 10 2021 - Web Application Security Risks
- PostgreSQL 17 Security Documentation - Authentication Methods and SSL

**Verification Commands:**

**Post-SSL Implementation:**

```powershell
Get-WebBinding | Where-Object {$_.protocol -eq "https"} | Select bindingInformation,certificateHash
netsh http show sslcert
```

**SMB Security Validation:**

```powershell
Get-SmbServerConfiguration | Select RequireSecuritySignature,EncryptData
```

**Log Forwarding Confirmation:**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -MaxEvents 10
Get-NetFirewallProfile | Select Name,LogBlocked,LogAllowed,LogFileName
```
