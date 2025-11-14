systemctl list-units --type=service --state=running --no-pager | grep -v systemd    # running non-systemd services
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null                                  # active listening sockets and owning processes
ip addr show                                                                         # network interface addresses
ip route show                                                                        # current routing table
cat /etc/resolv.conf                                                                 # primary DNS configuration
systemd-resolve --status 2>/dev/null | grep -A5 "DNS Servers"                        # detailed DNS server status from systemd-resolved