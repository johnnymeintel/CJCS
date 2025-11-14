lsb_release -a                                             # distro release and codename
uname -a                                                   # kernel version and architecture
uptime                                                     # system uptime and load average
lscpu | egrep Model\ name\|CPU\(s\)\|Thread\|Core          # CPU model, cores, threads
free -h                                                    # memory and swap usage
df -h                                                      # disk usage and mount points
hostnamectl                                                # hostname, OS version, virtualization info
systemd-detect-virt                                        # detect virtualization type
whoami                                                    # current logged-in user
id                                                         # user and group memberships
ip -brief addr                                             # network interfaces and IP addresses
ip route                                                   # current routing table
timedatectl                                                # timezone and NTP sync status
lsblk -f                                                   # block devices, filesystem types, free space
mount | egrep noexec\|nosuid\|nodev                        # secure mount options in effect
journalctl -b -p err                                       # errors and warnings since last boot
systemctl list-units --type=service --state=running --no-pager  # running services
getent passwd root                                         # root account shell and home directory
getent group sudo                                          # list of users with sudo privileges
dpkg -l | egrep wazuh\|ossec                               # installed Wazuh or OSSEC packages and versions
snap list 2>/dev/null || true                              # installed snap packages (if any)
ss -tulpn                                                  # listening sockets and owning processes
sysctl kernel.kptr_restrict                                # restricts leaking kernel pointers
sysctl kernel.dmesg_restrict                               # controls access to kernel logs
sysctl kernel.unprivileged_bpf_disabled                    # restricts unprivileged BPF usage
cat /etc/resolv.conf                                       # current DNS resolver configuration
systemd-resolve --status 2>/dev/null | sed -n '1,80p'      # detailed systemd-resolved DNS status
