Get-ADUser -Identity psql_svc -Properties ServicePrincipalName,PasswordLastSet,MemberOf | 
  Select-Object Name,
    @{Name="SPNs";Expression={$_.ServicePrincipalName -join "; "}},
    PasswordLastSet,
    @{Name="PasswordAge";Expression={((Get-Date) - $_.PasswordLastSet).Days}},
    @{Name="InPrivilegedGroup";Expression={$_.MemberOf -match "Domain Admins|Enterprise Admins"}}