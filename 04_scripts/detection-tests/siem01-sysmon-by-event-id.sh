grep -i "sysmon" /var/ossec/logs/archives/archives.json | jq -r '.data.win.eventdata.eventID // .data.win.system.eventID // empty' | sort | uniq -c
