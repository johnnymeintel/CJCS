tail -n2000 /var/ossec/logs/alerts/alerts.json \
| grep -E '^\{' \
| jq -r '.agent.name' \
| sort | uniq -c | sort -nr