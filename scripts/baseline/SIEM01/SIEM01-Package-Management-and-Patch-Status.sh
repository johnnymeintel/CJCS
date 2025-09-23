apt list --upgradable 2>/dev/null | grep -i security    # available security updates
grep " install " /var/log/dpkg.log | tail -20           # recently installed packages
cat /etc/apt/sources.list                               # package sources (main repository list)
ls -la /etc/apt/sources.list.d/ 2>/dev/null             # extra source files (PPA or vendor repos)
grep -E "(Allowed-Origins|Automatic-Reboot)" /etc/apt/apt.conf.d/*unattended* 2>/dev/null  # auto update / unattended-upgrade policy
