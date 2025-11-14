klist                                                           # list Kerberos tickets (TGT + service tickets) for pass-the-ticket visibility
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue   # check LSA Protected Process Light (RunAsPPL) status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue   # report Device Guard / VBS credential protection state
cmdkey /list                                                    # enumerate stored Credential Manager entries accessible to current user
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue   # cached logons count (offline logon capability)
