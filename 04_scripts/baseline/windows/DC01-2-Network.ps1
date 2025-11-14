# Check SMBv1 status (WannaCry/NotPetya vulnerability)
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature

# Check RDP security
Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting | 
  Select-Object TerminalName,UserAuthenticationRequired

# Check that things are not only blocked by the firewall but recorded
Get-NetFirewallProfile | Select-Object Name,Enabled,LogAllowed,LogBlocked