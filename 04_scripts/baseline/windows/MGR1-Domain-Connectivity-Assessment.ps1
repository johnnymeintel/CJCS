Test-NetConnection dc01.cjcs.local -Port 389  # LDAP authentication
Test-NetConnection dc01.cjcs.local -Port 445  # SMB file sharing
Test-NetConnection dc01.cjcs.local -Port 53   # DNS resolution