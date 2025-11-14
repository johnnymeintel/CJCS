Get-ADUser -Identity $env:USERNAME -Properties MemberOf,AdminCount   # AD groups and AdminCount flag for current user
Get-LocalGroupMember "Administrators" | Select-Object Name,PrincipalSource,ObjectClass   # enumerate local Administrators and origin
net localgroup administrators                                         # show local Administrators (fallback for older systems)
whoami /priv | findstr "SeDebug SeBackup SeRestore SeTakeOwnership SeImpersonate"   # list presence of high-risk privileges
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordExpires   # local accounts and basic password policy state
