ls -la /etc/passwd /etc/shadow /etc/group                             # check permissions and ownership of core account and group files
egrep -v '^(#|$)' /etc/sudoers                                         # show active sudoers configuration lines (no comments/blank lines)
ls -la /etc/ssh/sshd_config /etc/crontab /etc/fstab 2>/dev/null        # verify permissions on critical configuration files