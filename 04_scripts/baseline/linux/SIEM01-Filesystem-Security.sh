mount | egrep 'noexec|nosuid|nodev'                                             # check secure mount options on critical filesystems
find /usr/bin /usr/sbin /bin /sbin -perm /6000 -type f 2>/dev/null | head -20   # list first 20 SUID/SGID binaries (privilege escalation risk)
find /etc /usr /var -type f -perm -0002 2>/dev/null | head -20                  # list first 20 world-writable files in key directories
ls -ld /etc /var/log /home /root /tmp                                           # verify permissions on critical directories