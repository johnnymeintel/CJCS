#!/bin/bash
# Split-pane view: Status top, events bottom - FIXED

# Print header once
print_header() {
    clear
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                    WAZUH MONITORING DASHBOARD                  ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
}

# Update status section
update_status() {
    echo ""
    echo "═══ AGENT STATUS ═══════════════════════════════════════════════"
    sudo /var/ossec/bin/agent_control -l | grep -E "ID:|Name|IP|Status"
    echo ""
    echo "═══ ALERT COUNT (Last 5 min) ══════════════════════════════════"
    sudo jq -r --arg cutoff "$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S)" \
        'select(.timestamp > $cutoff) | .rule.id' /var/ossec/logs/alerts/alerts.json 2>/dev/null | 
        sort | uniq -c | sort -rn | head -5 | awk '{printf "  Rule %-6s: %3d alerts\n", $2, $1}'
    echo "═══ LIVE SYSMON EVENTS ════════════════════════════════════════"
    printf "%-10s %-12s %-6s %-25s %-15s\n" "TIME" "HOST" "EVT" "PROCESS" "USER"
    printf "%-10s %-12s %-6s %-25s %-15s\n" "----" "----" "---" "-------" "----"
}

# Initial setup
print_header
update_status

# Counter for status refresh
counter=0

# Stream events and refresh status periodically
sudo tail -f /var/ossec/logs/archives/archives.json | 
    grep --line-buffered -i "sysmon" | 
    jq -c '
        def safeget($path): try .data.win.eventdata[$path] catch null;
        
        # Filter out noise
        select(
            (safeget("image") // safeget("sourceImage") // "" | 
             test("whoami|taskhostw|SecurityHealthHost|smartscreen|WindowsPackageManager|VBoxService"; "i") | not)
        ) |
        
        {
            t: (.timestamp | split("T")[1] | split(".")[0]),
            host: (.agent.name | split(".")[0]),
            evt: .data.win.system.eventID,
            proc: (
                safeget("image") // 
                safeget("sourceImage") // 
                safeget("targetImage") // 
                "?" | 
                gsub("\\\\\\\\"; "/") | 
                split("/") | 
                last
            ),
            user: (
                safeget("user") // 
                safeget("sourceUser") // 
                safeget("targetUser") // 
                "?" | 
                gsub("\\\\\\\\"; "/") | 
                split("/") | 
                last
            )
        }' | while read -r line; do
            # Print event
            echo "$line" | jq -r '[.t, .host, .evt, .proc, .user] | @tsv' | 
                awk '{printf "%-10s %-12s %-6s %-25s %-15s\n", $1, $2, $3, $4, $5}'
            
            # Refresh status every ~25 events (approximately 5 seconds with moderate activity)
            counter=$((counter + 1))
            if [ $((counter % 25)) -eq 0 ]; then
                print_header
                update_status
            fi
        done