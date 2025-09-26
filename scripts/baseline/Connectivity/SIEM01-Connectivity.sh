# Network connectivity validation to Windows systems
nc -zv 192.168.100.10 88
nc -zv 192.168.100.10 53
nc -zv 192.168.100.20 80
nc -zv 192.168.100.20 5432
nc -zv 192.168.100.101 3389

# DNS resolution validation using proper DNS server
dig @192.168.100.10 dc01.cjcs.local A
dig @192.168.100.10 app01.cjcs.local A
dig @192.168.100.10 win11-mgr1.cjcs.local A
dig @192.168.100.10 cjcs.local SOA
dig @192.168.100.10 _kerberos._tcp.cjcs.local SRV

# Wazuh agent connectivity ports
ss -tuln | grep -E ":1514|:1515"

# Time synchronization status
timedatectl status

# Network interface status
ip addr
ip route

# System resources
free -h
df -h
uptime