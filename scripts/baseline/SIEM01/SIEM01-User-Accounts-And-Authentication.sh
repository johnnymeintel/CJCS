getent passwd | egrep ':(/bin/bash|/bin/sh)$'                          # human login-capable accounts
for g in sudo admin wheel root docker; do getent group $g >/dev/null && echo "$g: $(getent group $g | cut -d: -f4)"; done   # membership in privileged groups
egrep 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' /etc/login.defs      # system-wide password policy
lastlog | head -20                                                     # recent successful logins
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -15        # recent failed login attempts