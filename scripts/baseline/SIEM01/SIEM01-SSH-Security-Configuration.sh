systemctl is-active sshd                                                          # check if SSH service is running
systemctl is-enabled sshd                                                         # check if SSH service is enabled at boot
egrep '^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication|Port|Protocol)' /etc/ssh/sshd_config | egrep -v '^#'   # critical SSH settings (root login, password login, keys, port, protocol)
ls -la /root/.ssh/ 2>/dev/null                                                    # inspect root's SSH key directory
ls -la /home/*/.ssh/ 2>/dev/null                                                  # inspect user SSH key directories
who                                                                               # list currently logged-in users
w                                                                                 # show current sessions with detailed activity
