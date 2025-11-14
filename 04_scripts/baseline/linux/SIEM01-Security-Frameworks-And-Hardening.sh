aa-status 2>/dev/null || echo "AppArmor not configured"                 # check if AppArmor mandatory access control is active
sestatus 2>/dev/null || echo "SELinux not installed (normal on Ubuntu)" # check SELinux status (expected absent on Ubuntu)
systemctl is-active fail2ban 2>/dev/null || echo "fail2ban not installed"   # check if fail2ban intrusion-prevention service is running
fail2ban-client status 2>/dev/null | head -10                           # show fail2ban global status and active jails