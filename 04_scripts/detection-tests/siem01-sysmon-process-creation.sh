display_combined() {
    sudo tail -f /var/ossec/logs/archives/archives.json | 
        grep --line-buffered -i "sysmon" | 
        jq -c --unbuffered '
            # Only show Event ID 1 (Process Creation)
            select(.data.win.system.eventID == "1") |
            {
                t: (.timestamp | split("T")[1] | split(".")[0] | split("-")[0]),
                host: (.agent.name | split(".")[0]),
                evt: .data.win.system.eventID,
                proc: (
                    .data.win.eventdata.image //
                    "?" |
                    gsub("\\\\\\\\"; "/") |
                    split("/") |
                    last
                ),
                cmdline: (
                    .data.win.eventdata.commandLine //
                    "" |
                    if length > 40 then .[0:40] + "..." else . end
                ),
                user: (
                    .data.win.eventdata.user //
                    "?" |
                    gsub("\\\\\\\\"; "/") |
                    split("/") |
                    last
                )
            }' | while read -r line; do
                clear
                cat "$STATUS_FILE" 2>/dev/null || echo "Status loading..."
                echo ""
                echo "════════════════════════════════════════════════════════════════"
                echo "            LIVE PROCESS CREATION EVENTS (Sysmon ID 1)          "
                echo "════════════════════════════════════════════════════════════════"
                
                echo "$line" >> /tmp/sysmon_events_$$
                tail -10 /tmp/sysmon_events_$$ | 
                    jq -r '[.t, .host, .proc, .user] | @tsv' | 
                    awk 'BEGIN {
                        printf "%-9s %-12s %-25s %-15s\n", 
                               "TIME", "HOST", "PROCESS", "USER"
                        printf "%-9s %-12s %-25s %-15s\n", 
                               "----", "----", "-------", "----"
                    }
                    {
                        printf "%-9s %-12s %-25s %-15s\n", 
                               $1, $2, $3, $4
                    }'
            done
}