sudo tail -f /var/ossec/logs/alerts/alerts.json \
 | jq -c 'select(.rule and ((.rule.id|tostring)=="100010" or (.rule.id|tostring)=="100002"))
         | {t:.timestamp, id:(.rule.id|tostring), desc:.rule.description, host:(.agent.name // "N/A"), user:(.data.win.eventdata.targetUserName // .data.win.eventdata.TargetUserName // "N/A") }'