lsmod | head -20                                              # list first 20 loaded kernel modules
egrep -i 'nx|smep|smap' /proc/cpuinfo | head -5               # check CPU support for NX, SMEP, SMAP protections
cat /proc/sys/kernel/randomize_va_space                       # verify ASLR (address space layout randomization) setting
cat /proc/sys/kernel/dmesg_restrict                           # check dmesg access restrictions
sudo dmesg | tail -20 2>/dev/null || echo "dmesg access restricted"    # show last 20 kernel log messages