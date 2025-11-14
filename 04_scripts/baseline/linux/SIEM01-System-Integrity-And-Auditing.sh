which aide && aide --version 2>/dev/null || echo "AIDE not installed"      # check if AIDE file-integrity tool is present and versioned
systemctl is-active auditd                                                 # check if audit daemon is running
auditctl -s 2>/dev/null | head -10                                         # show auditd status and rule summary
debsums -s 2>/dev/null | head -20 || echo "debsums not installed"          # verify package integrity if debsums is available