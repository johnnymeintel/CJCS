ufw status verbose 2>/dev/null || echo "UFW not installed/configured"   # check UFW firewall status and rules
iptables -L -n                                                          # list current iptables firewall chains and rules
sysctl net.ipv4.ip_forward                                              # verify IPv4 packet forwarding (should be 0 for a host)
sysctl net.ipv4.conf.all.send_redirects                                 # check if ICMP redirect sending is allowed
sysctl net.ipv4.conf.all.accept_redirects                               # check if host accepts ICMP redirects
sysctl net.ipv4.conf.all.accept_source_route                             # check if host accepts source-routed packets