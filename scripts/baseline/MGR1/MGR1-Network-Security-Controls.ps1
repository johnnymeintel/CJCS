Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections   # RDP enabled? (0 = allow, 1 = deny)
Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Select-Object DisplayName,Enabled,Direction,Action   # firewall rules for Remote Desktop (enabled/blocked and direction)
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction   # firewall profiles and default inbound/outbound policies
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature   # SMB server settings: SMBv1 enabled and whether signing is required
