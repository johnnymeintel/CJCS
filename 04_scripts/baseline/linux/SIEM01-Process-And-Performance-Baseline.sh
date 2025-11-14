ps auxf | head -30                                   # show top 20 processes in tree form for parent/child relationships
ps aux --sort=-%cpu | head -15                       # list highest CPU and memory consumers
ss -tulpn | grep LISTEN | head -20                   # display listening processes with network context (ports and PIDs)