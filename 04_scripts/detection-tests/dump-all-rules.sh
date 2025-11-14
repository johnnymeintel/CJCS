#!/bin/bash
# Dump all Wazuh rule IDs, levels, and descriptions to a CSV file
# Output: /var/ossec/logs/wazuh_rules.csv

output="/var/ossec/logs/wazuh_rules.csv"
echo "RuleID,Level,Description,File" > "$output"

# Scan through both default and local rule directories
sudo grep -R --include="*.xml" -E '<rule\s+id="|<description>' /var/ossec/{ruleset,etc}/rules/ \
| awk '
    /<rule / {
        match($0, /id="([0-9]+)"/, id)
        match($0, /level="([0-9]+)"/, lvl)
        rule_id=id[1]; level=lvl[1]; next
    }
    /<description>/ {
        match($0, /<description>([^<]+)<\/description>/, desc)
        description=desc[1]
        if (rule_id != "") {
            gsub(/,/, " ", description)  # sanitize commas
            print rule_id "," level "," description "," FILENAME
        }
    }' | sort -n >> "$output"

echo "✅ Done. Saved to $output"
echo "Use: cat $output | column -t -s',' | less -S"
