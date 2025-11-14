sudo tail -f /var/ossec/logs/alerts/alerts.json \
 | grep -i 4625 \
 | jq -c '
    select(.full_log)
    | {
        t: .timestamp,
        host: (.agent.name // "N/A"),
        id: (.rule.id // "N/A"),
        user: (.data.win.eventdata.targetUserName // .data.win.eventdata.TargetUserName // "N/A"),
        src_ip: (.data.win.eventdata.ipAddress // "N/A")
      }'