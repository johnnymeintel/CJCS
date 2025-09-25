systemctl is-active wazuh-manager || echo "wazuh-manager not installed"   # service state (running/active) or not present
ls -la /var/ossec/ 2>/dev/null | head -20                                 # Wazuh install dir: ownership/permissions (top entries)
ls -la /etc/wazuh-manager/ 2>/dev/null                                     # Wazuh manager config dir: verify perms and presence of config files
ps aux | egrep '(wazuh|ossec)' | grep -v egrep                             # running Wazuh/OSSEC processes and owning users