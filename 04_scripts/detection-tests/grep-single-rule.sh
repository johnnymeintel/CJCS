# Quick check - is there activity?
# sudo grep -F '"id":"100010"' /var/ossec/logs/alerts/alerts.json | tail -n 20 | jq '.'

# Detailed analysis - read through formatted output
sudo grep -F '"id":"100010"' /var/ossec/logs/alerts/alerts.json | tail -n 20 | jq '.' | less

# Saved for later - pipe to file instead
# sudo grep -F '"id":"100010"' /var/ossec/logs/alerts/alerts.json | tail -n 20 | jq '.' > rule_100010_review.json