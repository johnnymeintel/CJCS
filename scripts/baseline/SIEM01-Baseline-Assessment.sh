#!/bin/bash
# SIEM01 Security Baseline Assessment - Cookie Jar Cloud Solutions
# Ubuntu 22.04 security evaluation for Wazuh SIEM deployment
# Author: Johnny Meintel
# Target: SIEM01.cjcs.local (192.168.100.5)

echo "==============================================================================="
echo "SIEM01 SECURITY ASSESSMENT - COOKIE JAR CLOUD SOLUTIONS"
echo "Target: $(hostname -f) ($(hostname -I | awk '{print $1}'))"
echo "Assessment Start: $(date)"
echo "==============================================================================="

# System Information
echo -e "\n=== SYSTEM IDENTIFICATION ==="
echo "OS Release:"
lsb_release -a 2>/dev/null
echo -e "\nKernel:"
uname -a
echo -e "\nUptime:"
uptime
echo -e "\nCPU:"
lscpu | grep -E "(Model name|CPU\(s\)|Core)"
echo -e "\nMemory:"
free -h
echo -e "\nDisk Usage:"
df -h

# Package Management
echo -e "\n=== PACKAGE MANAGEMENT ==="
echo "Available Security Updates:"
apt list --upgradable 2>/dev/null | grep -i security | head -10
echo -e "\nRecent Package Installations:"
grep " install " /var/log/dpkg.log | tail -10
echo -e "\nPackage Sources:"
cat /etc/apt/sources.list | grep -v "^#" | grep -v "^$"
echo -e "\nAutomatic Updates:"
cat /etc/apt/apt.conf.d/*unattended* 2>/dev/null | grep -E "(Allowed-Origins|Automatic-Reboot)"

# User Account Security
echo -e "\n=== USER ACCOUNTS ==="
echo "Shell Users:"
cat /etc/passwd | grep -E "(sh$|bash$)" | cut -d: -f1,3,7
echo -e "\nPrivileged Groups:"
for group in sudo admin wheel root docker; do
    if getent group $group >/dev/null 2>&1; then
        echo "$group: $(getent group $group | cut -d: -f4)"
    fi
done
echo -e "\nPassword Policy:"
grep -E "(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)" /etc/login.defs
echo -e "\nRecent Logins:"
lastlog | head -10
echo -e "\nFailed Login Attempts:"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5

# SSH Configuration
echo -e "\n=== SSH CONFIGURATION ==="
echo "SSH Service:"
systemctl is-active sshd
systemctl is-enabled sshd
echo -e "\nSSH Settings:"
grep -E "(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)" /etc/ssh/sshd_config | grep -v "^#"
echo -e "\nSSH Keys:"
ls -la /home/*/.ssh/ 2>/dev/null | head -5
echo -e "\nActive Sessions:"
who

# Network Services
echo -e "\n=== NETWORK SERVICES ==="
echo "Running Services:"
systemctl list-units --type=service --state=running --no-pager | grep -v "systemd" | head -15
echo -e "\nListening Ports:"
ss -tlnp | head -15
echo -e "\nNetwork Interfaces:"
ip addr show | grep -E "(inet |^[0-9])"
echo -e "\nDNS Configuration:"
cat /etc/resolv.conf | grep -v "^#"

# Firewall Status
echo -e "\n=== FIREWALL ==="
echo "UFW Status:"
ufw status verbose 2>/dev/null || echo "UFW not configured"
echo -e "\niptables Rules:"
iptables -L -n | head -15
echo -e "\nNetwork Security Parameters:"
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.accept_redirects

# File System Security
echo -e "\n=== FILE SYSTEM ==="
echo "Secure Mount Options:"
mount | grep -E "(noexec|nosuid|nodev)"
echo -e "\nSUID/SGID Binaries:"
find /usr/bin /usr/sbin /bin /sbin -perm /6000 -type f 2>/dev/null | head -10
echo -e "\nWorld-Writable Files:"
find /etc /var -type f -perm -002 2>/dev/null | head -5
echo -e "\nCritical Directory Permissions:"
ls -ld /etc /var/log /root /tmp

# Wazuh SIEM Status
echo -e "\n=== WAZUH SIEM ==="
echo "Wazuh Services:"
systemctl is-active wazuh-manager 2>/dev/null || echo "wazuh-manager: not installed"
systemctl is-active wazuh-indexer 2>/dev/null || echo "wazuh-indexer: not installed"
systemctl is-active wazuh-dashboard 2>/dev/null || echo "wazuh-dashboard: not installed"
echo -e "\nWazuh Directory Permissions:"
ls -la /var/ossec/ 2>/dev/null | head -5
echo -e "\nWazuh Processes:"
ps aux | grep -E "(wazuh|ossec)" | grep -v grep

# Log File Security
echo -e "\n=== LOG SECURITY ==="
echo "Critical Log Permissions:"
ls -la /var/log/auth.log /var/log/syslog 2>/dev/null
echo -e "\nLog Rotation:"
cat /etc/logrotate.conf | grep -E "(rotate|size)" | head -3
echo -e "\nLog Storage:"
df -h /var/log

# System Integrity
echo -e "\n=== SYSTEM INTEGRITY ==="
echo "File Integrity Monitoring:"
which aide && aide --version 2>/dev/null || echo "AIDE not installed"
echo -e "\nAudit Daemon:"
systemctl is-active auditd
auditctl -s 2>/dev/null | head -3

# Process Analysis
echo -e "\n=== RUNNING PROCESSES ==="
echo "Top CPU Processes:"
ps aux --sort=-%cpu | head -8
echo -e "\nNetwork Connections:"
netstat -tulpn 2>/dev/null | grep LISTEN | head -10

# Kernel Security
echo -e "\n=== KERNEL SECURITY ==="
echo "Loaded Modules:"
lsmod | head -10
echo -e "\nSecurity Features:"
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
echo -e "\nRecent Kernel Messages:"
dmesg | tail -5

# Scheduled Tasks
echo -e "\n=== SCHEDULED TASKS ==="
echo "System Cron Jobs:"
ls -la /etc/cron.* 2>/dev/null | head -5
crontab -l 2>/dev/null || echo "No root crontab"

# Development Tools
echo -e "\n=== DEVELOPMENT TOOLS ==="
echo "Compilers/Interpreters:"
which gcc python3 perl ruby 2>/dev/null || echo "Standard dev tools not found"

# Container Security
echo -e "\n=== CONTAINERS ==="
echo "Docker Status:"
systemctl is-active docker 2>/dev/null || echo "Docker not installed"
docker ps 2>/dev/null | head -3 || echo "Docker not accessible"

# Security Hardening
echo -e "\n=== SECURITY HARDENING ==="
echo "AppArmor:"
aa-status 2>/dev/null | head -5 || echo "AppArmor not configured"
echo -e "\nFail2ban:"
systemctl is-active fail2ban 2>/dev/null || echo "Fail2ban not installed"

# Time Synchronization
echo -e "\n=== TIME SYNC ==="
timedatectl status | grep -E "(System clock|NTP service)"
echo -e "\nNTP Sources:"
cat /etc/systemd/timesyncd.conf 2>/dev/null | grep -E "NTP"

# Configuration Security
echo -e "\n=== CONFIGURATION SECURITY ==="
echo "Password Files:"
ls -la /etc/passwd /etc/shadow /etc/group
echo -e "\nSudo Configuration:"
cat /etc/sudoers | grep -v "^#" | grep -v "^$" | head -5

echo -e "\n==============================================================================="
echo "ASSESSMENT COMPLETE: $(date)"
echo "==============================================================================="