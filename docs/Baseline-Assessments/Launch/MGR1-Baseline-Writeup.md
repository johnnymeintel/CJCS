### 🏷 WIN11-MGR1 - Executive Workstation - Baseline Security Assessment – Cookie Jar Cloud Solutions

**Target Host:** [win11-mgr1.cjcs.local 192.168.100.101/24] 
**Assessment Date:** 09/25/2025 
**Author:** John David Meintel Jr / Security Support Specialist for Cookie Jar Cloud Solutions 
**System Role:** Primary workstation for company executive (CEO)

---

## 1. Executive Summary

**Critical Risk Assessment:** MGR1 represents the typical over-privileged executive workstation. The virtual environment is intentionally vulnerable as it accurately mirrors a common poor practice within information security of a lack of separation of duties. 

**Primary Risk Vectors:**

- **Privileged Account Exposure** - Current user (mchen) holds Domain Admin rights on daily-use workstation, violating principle of least privilege.
- **Remote Access Vulnerabilities** - RDP enabled with default firewall exceptions and no network-level authentication creates potential entry point for credential-based attacks.
- **Endpoint Protection Gaps** - Limited visibility into endpoint detection capabilities and real-time threat monitoring due to a lack of centralized logging.
- **Data Exfiltration Risk** - Executive workstation likely contains sensitive business data and credentials for critical systems.
- **Social Engineering Target** - High-profile user makes system prime target for spear phishing and targeted attacks.

**Compliance Impact:** Three SOC 2 control failures around privileged access management (CC6.2), endpoint monitoring (CC7.1), and data classification (CC6.7). Executive workstation security gaps could fail audit requirements for protecting sensitive customer and business data.

**Business Risk:** Executive workstation compromise could result in complete domain takeover, intellectual property theft, and regulatory violations that threaten CJCS's ability to maintain customer trust and business operations.

---

## 2. Scope & Methodology

**System Type:** Windows 11 Professional domain-joined executive workstation.

**Assessment Approach:** PowerShell-based security assessment using built-in Windows utilities, focused on endpoint security posture and privileged access risk management.

**Focus Areas:**

- **Privileged Access Risk** - Domain administrator account usage patterns and separation of duties validation
- **Endpoint Security Controls** - Local security policies, remote access configuration, and threat detection capabilities
- **Data Protection** - Executive data handling, encryption status, and information classification controls
- **Network Security Posture** - Firewall configuration, service exposure, and domain connectivity security

**Evidence Location:** 13 PowerShell assessment scripts with detailed endpoint security results, providing executive risk documentation for immediate remediation and compliance validation.

---

## 3. System Identification

```powershell
Get-ComputerInfo | Select-Object WindowsProductName,TotalPhysicalMemory,CsProcessors,CsDomain,CsWorkgroup   # OS name, total RAM, CPU count, and AD/workgroup membership
Test-ComputerSecureChannel -Verbose                                    # confirm AD Kerberos secure channel is healthy
$env:USERNAME; $env:USERDOMAIN                                         # current username and Windows domain
Get-NetIPAddress | Where-Object AddressFamily -eq "IPv4" | Select-Object IPAddress,InterfaceAlias   # list IPv4 addresses and network interfaces
whoami /groups                                                         # show all group memberships for current user
Get-NetAdapter | Select-Object Name,Status,LinkSpeed,MediaType         # network adapter names, link state, speed, and type
```

- **Operating system**: System > About UI shows Windows 11 Pro, PowerShell `Get-ComputerInfo` reveals Windows 10 Pro - joined to cjcs.local domain.
- **Hardware**: 11th Gen Intel i5-11400F CPU; two active network adapters (10.0.3.15 NAT, 192.168.100.101 bridged).
- **Security context**: User mchen belongs to CJCS\Domain Admins, BUILTIN\Administrators, and standard built-in Windows groups, providing **excessive administrative privileges** for an executive workstation.
- **Network interfaces**: All physical adapters are Up and report 1 Gbps link speed.
- **Domain membership**: Confirmed via `Test-ComputerSecureChannel` - secure channel to DC01 operational, enabling AD authentication and group policy enforcement.

---

## 4. Privilege Escalation Analysis

```powershell
Get-ADUser -Identity $env:USERNAME -Properties MemberOf,AdminCount   # AD groups and AdminCount flag for current user
Get-LocalGroupMember "Administrators" | Select-Object Name,PrincipalSource,ObjectClass   # enumerate local Administrators and origin
net localgroup administrators                                         # show local Administrators (fallback for older systems)
whoami /priv | findstr "SeDebug SeBackup SeRestore SeTakeOwnership SeImpersonate"   # list presence of high-risk privileges
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordExpires   # local accounts and basic password policy state
```

- **Domain account**: mchen (Marcus Chen) is enabled, AdminCount=1, and a direct member of CJCS\Domain Admins.
- **Local administrators**: Built-in Administrator, CJCS\Domain Admins group, and a local PNWMGR1 account have full local admin rights.
- **Privilege tokens**: SeDebugPrivilege and SeImpersonatePrivilege are enabled, allowing process debugging and impersonation—both common lateral-movement vectors.
- **Local accounts**: Default Administrator is disabled, Guest and DefaultAccount are disabled, PNWMGR1 is enabled with password not required.

---

## 5. Cached Credential Exposure

```powershell
klist                                                           # list Kerberos tickets (TGT + service tickets) for pass-the-ticket visibility
Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue   # check LSA Protected Process Light (RunAsPPL) status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue   # report Device Guard / VBS credential protection state
cmdkey /list                                                    # enumerate stored Credential Manager entries accessible to current user
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue   # cached logons count (offline logon capability)

```

- **Cached Kerberos tickets**: TGTs present for `mchen@CJCS.LOCAL` (krbtgt) with AES-256 encryption. Tickets are **forwardable** and **renewable**, and one ticket shows `ok_as_delegate` for `ldap/DC01.cjcs.local` — delegation is enabled. Ticket lifetimes include 10-hour initial and 7-day renewable, indicating standard executive access patterns.
- **LSA PPL / Device Guard**: `RunAsPPL : 2` is present in the Lsa registry output; Device Guard / VBS reports no active virtualization-based protection.
- **Stored credentials**: Credential Manager contains a Generic entry (`WindowsLive:target=virtualapp/didlogical`) persisted to the local machine.
- **Cached logons**: `CachedLogonsCount = 10` — up to ten cached domain credentials are retained for offline logins.

---

## 6. Application Attack Surface

```powershell
Get-Process | Where-Object {$_.Company -ne "Microsoft Corporation" -and $_.ProcessName -ne "Idle" -and $_.ProcessName -ne "System"} | Select-Object Name,Id,CPU,WorkingSet,Path,Company | Sort-Object CPU -Descending   # list non-Microsoft processes sorted by CPU (third-party process inventory)
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | ForEach-Object { $Process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [PSCustomObject]@{ LocalPort = $_.LocalPort; ProcessName = $Process.ProcessName; ProcessPath = $Process.Path; ProcessCompany = $Process.Company } } | Sort-Object LocalPort   # map listening TCP ports to process name/path/company (attack-surface view)
$procByPid = Get-CimInstance Win32_Process | Group-Object -Property ProcessId -AsHashTable -AsString   # build PID→process lookup table for fast correlation
Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object { $p = $procByPid[[string]$_.OwningProcess]; [PSCustomObject]@{ LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; PID = $_.OwningProcess; ProcessName = $p.Name; ExecutablePath = $p.ExecutablePath } }   # efficient port→process table using CIM cache (reduces repeated Get-Process calls)
Get-WmiObject Win32_Service | Where-Object {$_.StartName -notlike "*LocalSystem*" -and $_.StartName -notlike "*LocalService*" -and $_.StartName -notlike "*NetworkService*"} | Select-Object Name,StartName,State,PathName   # enumerate services running under explicit user accounts (privilege/persistence risk)
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User   # enumerate autostart entries (common persistence locations)
```

- **Third-party processes**: Only Oracle VirtualBox components (`VBoxService.exe`, `VBoxTray.exe`) are running outside Microsoft’s trusted code base.
- **Network listeners and ports**: RDP service on TCP/3389; SMB/RPC on TCP/139 and 445; plus standard ephemeral RPC ports (135, 496xx). OneDrive listener is limited to loopback.
- **Services running under user accounts**: None. All persistent services run under LocalSystem, NetworkService, or LocalService.
- **Autostart entries**: Standard Microsoft items (SecurityHealth, OneDrive, Edge) and VirtualBox guest utilities.

---

## 7. Endpoint Protection Assessment

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanAge,FullScanAge   # Windows Defender status and last-scan/signature recency
Get-WmiObject -Class AntiVirusProduct -Namespace "root\\SecurityCenter2" | Select-Object displayName,productState   # enumerate registered AV products and reported product state via SecurityCenter2
```

- **Antivirus and real-time protection**: Microsoft Defender is enabled with real-time protection active.
- **Signature currency**: Virus definitions updated 9/23/2025 18:14 UTC.
- **Scanning**: Last quick scan was 4 days ago; no recorded full scan (default 4,294,967,295 days means never).
- **Product state**: Windows Security Center reports product state code 397568, indicating healthy and up-to-date.

---

## 8. Network Security Controls

```powershell
Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections   # RDP enabled? (0 = allow, 1 = deny)
Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Select-Object DisplayName,Enabled,Direction,Action   # firewall rules for Remote Desktop (enabled/blocked and direction)
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction   # firewall profiles and default inbound/outbound policies
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature   # SMB server settings: SMBv1 enabled and whether signing is required
```

- **Remote Desktop configuration**: `fDenyTSConnections` is set to 0, so RDP is enabled at the OS level.
- **Firewall rules**:
    - Remote Desktop – User Mode (TCP-In, UDP-In) is enabled and allowed inbound.
    - Other RDP rules such as TCP-WS-In and TCP-WSS-In are disabled.
- **Firewall profiles**: Domain, Private, and Public profiles are enabled; default inbound and outbound actions are not explicitly set (inherit defaults).
- **SMB settings**: SMBv1 is disabled (`EnableSMB1Protocol: False`), and SMB signing is enforced (`RequireSecuritySignature: True`).

---

## 9. Data Protection Controls

```powershell
Get-BitLockerVolume | Select-Object MountPoint,EncryptionMethod,VolumeStatus,ProtectionStatus   # report BitLocker status and protection state for each volume
cipher /u                                                                               # report any files/folders encrypted with EFS under the current user profile
```

- **BitLocker encryption active but protection disabled** - C: drive shows FullyEncrypted status with XtsAes128 method but ProtectionStatus: Off
- **No EFS file-level encryption detected** - cipher /u returns no encrypted files under current user profile
- **Security gap**: Encryption key accessible without authentication, negating full-disk encryption benefits

---

## 10. Registry Persistence Analysis

```powershell
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -ErrorAction SilentlyContinue        # list system-wide auto-start entries for all users
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" -ErrorAction SilentlyContinue   # check alternate system-wide autorun location
Get-ItemProperty "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -ErrorAction SilentlyContinue        # list per-user auto-start entries for current user
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" | Select-Object Userinit,Shell  # confirm shell and Userinit settings to detect persistence or hijack attempts
```

- **System-wide startup entries**: SecurityHealth (Windows Defender tray) and VBoxTray (VirtualBox integration) - both legitimate Windows/VirtualBox components
- **No alternate persistence locations detected** - HKLM\Policies\Explorer\Run registry key empty
- **User-specific startup entries**: Microsoft Edge auto-launch and OneDrive background sync for mchen account - standard productivity applications
- **Shell integrity confirmed** - Userinit.exe and explorer.exe settings match Windows defaults, no evidence of shell hijacking or logon process manipulation
- **Persistence baseline**: Standard Windows and productivity software auto-start entries with no suspicious third-party additions detected

---

## 11. Patch Management Status

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledOn | Select-Object -First 10   # list the 10 most recently installed Windows updates and hotfixes
Get-Service wuauserv | Select-Object Name,Status,StartType                                              # check if Windows Update (wuauserv) service is running and its startup type
```

- **Recent security updates applied** - KB5065426 and KB5065381 security patches installed September 2025, indicating active patch management
- **Mixed update types deployed** - combination of security updates and general system updates from September 7th and 20th installation cycles
- **Current patch level** - system shows recent September 2025 updates, suggesting reasonably current patch status for executive workstation
- **Windows Update service status** - wuauserv service information not displayed in output, requires verification of automatic update configuration

---

## 12. Domain Connectivity Assessment

```powershell
Test-NetConnection dc01.cjcs.local -Port 389  # LDAP authentication
Test-NetConnection dc01.cjcs.local -Port 445  # SMB file sharing
Test-NetConnection dc01.cjcs.local -Port 53   # DNS resolution
```

- **LDAP authentication successful** - Port 389 connectivity to DC01 confirmed, enabling Active Directory authentication and group policy application
- **SMB file sharing accessible** - Port 445 connection established for domain file shares and administrative access to domain controller
- **DNS resolution operational** - Port 53 connectivity verified, ensuring hostname resolution and domain service discovery
- **Network path confirmed** - All connections route through Ethernet interface from workstation (192.168.100.101) to domain controller (192.168.100.10)
- **Domain services baseline** - Critical domain infrastructure accessible for authentication, file sharing, and name resolution functions

---

## 13. Security Event Analysis

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 10 | Select-Object TimeCreated,Id,Message       # show last 10 logon (4624) and failed logon (4625) security events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 10 | Select-Object TimeCreated,Message               # show last 10 process creation (4688) events for new program executions
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3} -MaxEvents 5 | Select-Object TimeCreated,LevelDisplayName,Message # show last 5 system errors (level 2) and warnings (level 3)
```

- **Recent authentication activity** - Multiple successful logons (Event ID 4624) recorded September 25th between 8:30-8:32 AM, showing active mchen user sessions during assessment period
- **Process creation burst** - Cluster of new process events at 8:14 AM indicates application startup or system service initialization during boot sequence
- **Windows update failures** - Installation failure for Microsoft Widgets Platform (error 0x80073D02) suggests update management issues requiring attention
- **Secure Boot firmware errors** - System firmware returned "Unspecified error" when updating Secure Boot variables, indicating potential UEFI security configuration problems
- **COM server permission warnings** - Multiple Local Launch permission denials for COM Server applications suggest service account privilege restrictions or misconfigurations
- **No failed authentication attempts detected** - Event ID 4625 logon failures absent from recent security logs, indicating no obvious brute force or credential attacks

---

## 14. Risk Assessment & Remediation

|Finding|Likelihood|Impact|Priority|Evidence|Remediation|
|---|---|---|---|---|---|
|Domain Admin Credential Exposure|H|H|P1|`whoami /groups` shows Domain Admins membership, `klist` reveals cached TGT tickets|Implement separate privileged accounts for executive functions, remove mchen from standing Domain Admin membership|
|Privilege Escalation Capabilities|H|H|P1|`whoami /priv` shows SeDebugPrivilege enabled allowing memory access|Disable SeDebugPrivilege, implement just-in-time admin access|
|RDP Attack Surface|M|H|P1|`Get-NetTCPConnection` shows port 3389 listening, fDenyTSConnections = 0|Disable RDP or restrict to management network with NLA|
|BitLocker Protection Disabled|L|M|P2|`Get-BitLockerVolume` shows ProtectionStatus: Off despite FullyEncrypted|Enable BitLocker authentication requirements|
|Weak Local Account Security|M|M|P2|PNWMGR1 account enabled with PasswordRequired: False|Disable unnecessary local accounts or enforce password policy|
|Excessive Cached Logons|L|M|P3|CachedLogonsCount: 10 allows extended offline access|Reduce cached logon count to 2-3 for improved security|

---

## 15. Detection & SOC Integration

**SIEM Rule Priorities:** • **Critical (P1) - Domain Admin Activity Monitoring:**

- Event ID 4672 - Special privileges assigned to logon (Domain Admin usage)
- Event ID 4648 - Explicit credential use (potential credential theft)
- Event ID 4688 - Process creation with administrative context
- Kerberos ticket anomalies indicating pass-the-ticket attacks

**High Priority (P2) - Privileged Access Events:** • Event ID 4624 - Interactive logons during off-hours • Event ID 4625 - Failed authentication attempts targeting CEO account (mchen) • Process creation events for credential dumping tools (mimikatz, procdump) • RDP connection attempts (Event ID 1149) from unauthorized sources

**Medium Priority (P3) - Baseline Monitoring:** • System startup and shutdown events • Application installation events • Network connection anomalies • USB device insertion events

**Lab-Appropriate Monitoring:** • Wazuh agent connectivity from MGR1 to SIEM01 • Windows event log forwarding verification • Domain controller authentication event correlation • Executive workstation activity baselines for anomaly detection

---

## 16. Compliance Impact

**SOC 2 Control Failures:**

**CC6.1 (Logical Access Controls) - CRITICAL FAILURE:** • Unrestricted Domain Admin access violates least privilege principle on executive endpoint • RDP enabled without network access controls exposes administrative credentials to remote attack • Evidence: `whoami /groups` shows Domain Admins membership, `Get-ItemProperty fDenyTSConnections` shows 0

**CC6.2 (Privileged Access Management) - CRITICAL FAILURE:**

• No separation between CEO business functions and domain administrative privileges • Cached credentials enable offline credential extraction and lateral movement • Evidence: `klist` shows active Domain Admin TGT tickets, SeDebugPrivilege enabled

**CC6.8 (Data Protection) - MODERATE FAILURE:** • BitLocker encryption configured but protection mechanisms disabled • Executive workstation data vulnerable despite encryption appearance • Evidence: `Get-BitLockerVolume` shows ProtectionStatus: Off

**Recommended Control Implementation:** • **Immediate (30 days)**: Remove standing Domain Admin rights, implement emergency break-glass accounts • **Short-term (90 days)**: Deploy Privileged Access Workstations (PAWs) for administrative tasks

• **Long-term (6 months)**: Implement just-in-time administrative access with approval workflows

---

## 17. Appendices

**References:** • NIST Cybersecurity Framework v1.1 - Identity Management ([ID.AM](http://ID.AM)) and Access Control ([PR.AC](http://PR.AC)) functions • Microsoft Security Compliance Toolkit - Windows 11 Executive Workstation baseline • SOC 2 Trust Services Criteria - Common Criteria 6 (Logical Access Controls) • CIS Controls v8 - Privileged Account Management guidelines

**Verification Commands:**

```powershell
# Verify Domain Admin membership removal
Get-ADGroupMember -Identity "Domain Admins" | Where-Object Name -eq "mchen"

# Confirm BitLocker protection enabled
Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus

# Validate RDP configuration
Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections

# Check privilege assignment
whoami /priv | findstr "SeDebug SeImpersonate"

# Verify cached logon reduction
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -Name CachedLogonsCount

```

**Post-Assessment Actions:**

1. Schedule quarterly privileged account access reviews
2. Document administrative workflow separation procedures
3. Prepare evidence package for SOC 2 auditor review of endpoint access controls
4. Update incident response procedures for executive workstation compromise scenarios

**Evidence Retention:**

- Assessment scripts and results: 3 years (compliance requirement)
- Configuration baselines: Until next major version upgrade
- Security incident logs: 7 years (regulatory requirement)