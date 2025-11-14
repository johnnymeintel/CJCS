ls -la /var/log/auth.log /var/log/syslog /var/log/kern.log 2>/dev/null    # check permissions and ownership of key log files
grep -E '^(weekly|daily|rotate|size|compress)' /etc/logrotate.conf 2>/dev/null   # view logrotate frequency, retention, compression settings
egrep '^[^#]' /etc/rsyslog.conf 2>/dev/null | head -20                   # display active rsyslog configuration lines
df -h /var/log                                                            # check free space and usage on /var/log partition