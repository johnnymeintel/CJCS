##### Basics

```
# Service status
systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

# Start/stop/restart quickly
sudo systemctl restart wazuh-manager
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-dashboard

# Manager version + sanity
/var/ossec/bin/wazuh-control info

# Manager: 1514/udp (events), 1515/tcp (legacy register), 55000/tcp (Wazuh API)
# Indexer: 9200/tcp (OpenSearch API)
# Dashboard: 443/tcp (web)
ss -tuln | grep -E ':(443|1514|1515|9200|55000)'

# Manager logs
tail -f /var/ossec/logs/ossec.log          # manager brains
tail -f /var/ossec/logs/api.log            # API server
tail -f /var/ossec/logs/active-responses.log

# Alerts (pretty + JSON)
tail -f /var/ossec/logs/alerts/alerts.log
tail -f /var/ossec/logs/alerts/alerts.json

# Rotated JSON (when hunting older stuff)
zgrep -a --no-filename . /var/ossec/logs/alerts/alerts.json*.gz | head

# Linux/Unix/macOS: Check the agent's current local connection status.
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state 

# Windows (PowerShell): Check the agent's current local connection status.
Select-String -Path 'C:\Program Files (x86)\ossec-agent\wazuh-agent.state' -Pattern "^status"
```

**Agent Enrollment**
```
# On manager: ensure registration is enabled (legacy 1515 or API 55000)
grep -E '^[^#]' /var/ossec/etc/ossec.conf | grep -A3 auth

# On Linux agent:
sudo /var/ossec/bin/agent-auth -m <MANAGER_IP> -A <AGENT_NAME> -p 1515
sudo systemctl restart wazuh-agent

# On Windows agent (elevated CMD):
"c:\Program Files (x86)\ossec-agent\agent-auth.exe" -m <MANAGER_IP> -A <AGENT_NAME> -p 1515
net stop wazuhsvc & net start wazuhsvc
```

**Paths to Remember**
```shell
/var/ossec/etc/                 # manager config, rules, decoders
/var/ossec/logs/ossec.log       # manager log
/var/ossec/logs/api.log         # API server log
/var/ossec/logs/alerts/*        # alerts (log + json + rotated gz)
/etc/wazuh-indexer/             # indexer configs + certs
/etc/wazuh-dashboard/           # dashboard configs
```
---
##### Alerts and Logs

```shell
# The essential utility for testing log parsing against decoders and rules. 
/var/ossec/bin/ossec-logtest 

# View real-time output of the Manager's internal operational log.
tail -f /var/ossec/logs/ossec.log 

# View real-time output of ALL raw collected logs (Archive Log - plaintext).
tail -f /var/ossec/logs/archives/archives.log 

# View real-time output of only events that successfully triggered an alert.
tail -f /var/ossec/logs/alerts/alerts.log
```


**Test Alert Generation**

```bash
# On SIEM01 - tail the alert log
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

**On MGR1:**

```powershell
# Generate Windows security events for testing
# 3x failed login attempts
1..3 | % { runas /user:SameUser cmd }

# Check locally
Get-EventLog -LogName System -Newest 5
```

**Alert Triage**

```
# Last alert (any type)
tail -n1 /var/ossec/logs/alerts/alerts.json | jq .

# Last N alerts, compact
tail -n20 /var/ossec/logs/alerts/alerts.json | jq -r '[.timestamp,.rule.id,.rule.level, .agent.name, .rule.description] | @tsv'

# Find failed Windows logon (4625) robustly (string or number)
jq -r 'select((.data.win.system.EventID // .data.win.system.eventID // empty | tostring)=="4625")
       | [.timestamp,.rule.id,.agent.name,.rule.description] | @tsv' \
  /var/ossec/logs/alerts/alerts.json | tail -n5

# Top noisy rules in last 1k lines
tail -n1000 /var/ossec/logs/alerts/alerts.json | jq -r '.rule.id' | sort | uniq -c | sort -nr | head

# Alerts by agent name
tail -n2000 /var/ossec/logs/alerts/alerts.json | jq -r '.agent.name' | sort | uniq -c | sort -nr
```

**Agent Management**

```
# List / status
/var/ossec/bin/manage_agents -l
/var/ossec/bin/agent_control -lc

# Force restart an agent connection from server (by ID)
/var/ossec/bin/agent_control -R -u <AGENT_ID>

# Remove a stale agent cleanly
/var/ossec/bin/manage_agents -r <AGENT_ID>
/var/ossec/bin/agent_control -R -u <AGENT_ID>  # kick after removal (optional)
```

**Log Rotation Verification**

```bash
# Check log rotation configuration
ls -la /etc/logrotate.d/wazuh*

# Verify log sizes are manageable
du -sh /var/ossec/logs/* 2>/dev/null | sort -h

df -h
free -m

```
---
##### API and Indexer

```shell
# Acquire a JSON Web Token (JWT) for subsequent API calls on port 55000.
curl -u <USER>:<PASS> -k -X POST "https://<HOST_IP>:55000/security/user/authenticate" 

# Check the health status of the Wazuh Indexer data cluster on port 9200.
curl -k -u <USER>:<PASS> https://localhost:9200/_cluster/health?pretty

# Handy: set creds once per shell (change these!)
export WZ_API="https://localhost:55000"
export WZ_USER="admin"
export WZ_PASS="yourpassword"

# Agents list (pretty)
curl -k -u $WZ_USER:$WZ_PASS "$WZ_API/agents?pretty"

# Agent details by name
curl -k -u $WZ_USER:$WZ_PASS "$WZ_API/agents?status=active&name=<AGENT_NAME>&pretty"

# Last 10 alerts via API search
curl -k -u $WZ_USER:$WZ_PASS "$WZ_API/alerts?limit=10&sort=timestamp:desc" | jq .

# Cluster health
curl -ksu admin:<password> https://localhost:9200/_cluster/health | jq .

# Indices (focus on wazuh-alerts-*)
curl -ksu admin:<password> "https://localhost:9200/_cat/indices?v"

# Delete oldest alert indices (space recovery) - BE CAREFUL
# Example deletes indices older than yyyy.mm.dd you specify:
for i in $(curl -ksu admin:<password> "https://localhost:9200/_cat/indices/wazuh-alerts-*?h=index" \
         | grep -E 'wazuh-alerts-[0-9]{4}\.[0-9]{2}\.[0-9]{2}' \
         | head -n 5); do
  curl -ksu admin:<password> -XDELETE "https://localhost:9200/$i";
done
```

---
##### Security

**Change Default Passwords**

```bash
# Generate new passwords for all Wazuh users
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --change-all

# Save new passwords securely
sudo cat /etc/wazuh-indexer/backup/wazuh-passwords.txt
```

**Disable Installation Repositories**

```bash
# Prevent accidental upgrades by disabling Wazuh repository
sudo sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
sudo apt update

# Verify repository is disabled
apt policy wazuh-manager | grep -i candidate
```

**SSL Certificate Replacement (Optional)**

```bash
# For production use, replace self-signed certificates
# This is optional for lab environment

# Backup existing certificates
sudo cp -r /etc/wazuh-indexer/certs /etc/wazuh-indexer/certs.backup
```
---
##### Troubleshooting

**Service Won't Start**

```bash
# Check service logs for errors
sudo journalctl -u wazuh-manager -n 50
sudo journalctl -u wazuh-indexer -n 50
sudo journalctl -u wazuh-dashboard -n 50

# Check Wazuh-specific logs
sudo tail -50 /var/ossec/logs/ossec.log
```

**Web Interface Inaccessible**

```bash
# Check dashboard service and port
sudo systemctl status wazuh-dashboard
sudo ss -tuln | grep 443

# Test certificate validity
openssl s_client -connect 192.168.100.5:443 -servername 192.168.100.5
```

**Agent Connection Issues**

```bash
# Check agent communication port
sudo ss -tuln | grep 1514

# Check firewall rules
sudo ufw status | grep 1514

# Review agent connection logs
sudo tail -50 /var/ossec/logs/ossec.log | grep -i agent
```

**High Resource Usage**

```bash
# Check system resources
top -p $(pgrep -d, -f wazuh)
df -h
free -m

# Check index size
curl -k -u admin:<password> "https://localhost:9200/_cat/indices?v"
```

```shell
# Services’ last 50 lines
journalctl -u wazuh-manager -n 50 --no-pager
journalctl -u wazuh-indexer -n 50 --no-pager
journalctl -u wazuh-dashboard -n 50 --no-pager

# Manager internal errors
tail -50 /var/ossec/logs/ossec.log

# Dashboard up + TLS port open
systemctl is-active wazuh-dashboard
ss -tuln | grep ':443\b'
openssl s_client -connect <DASHBOARD_IP>:443 -servername <DASHBOARD_IP> </dev/null | head -n 10

# Agent comms
ss -tuln | grep -E ':1514\b|:1515\b'
sudo ufw status | grep -E '1514|1515' || true
grep -i agent /var/ossec/logs/ossec.log | tail -50
```
---
##### Backup 
```bash
# Create backup script
cat << 'EOF' > ~/wazuh-backup.sh
#!/bin/bash
BACKUP_DIR="/opt/wazuh-backup-$(date +%Y%m%d)"
sudo mkdir -p $BACKUP_DIR

# Backup configurations
sudo cp -r /var/ossec/etc $BACKUP_DIR/ossec-etc
sudo cp -r /etc/wazuh-indexer $BACKUP_DIR/indexer-config
sudo cp -r /etc/wazuh-dashboard $BACKUP_DIR/dashboard-config

# Backup SSL certificates
sudo cp -r /etc/wazuh-indexer/certs $BACKUP_DIR/certificates

echo "Backup completed: $BACKUP_DIR"
EOF

chmod +x ~/wazuh-backup.sh
./wazuh-backup.sh
```
---
##### Quick Verification Checklist

```bash
# Run this complete verification
{
echo "=== WAZUH INSTALLATION VERIFICATION ==="
echo "Date: $(date)"
echo ""
echo "=== SERVICE STATUS ==="
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard
echo ""
echo "=== LISTENING PORTS ==="
ss -tuln | grep -E ':(443|1514|1515|9200|55000)'
echo ""
echo "=== AGENT STATUS ==="
/var/ossec/bin/manage_agents -l
echo ""
echo "=== RESOURCE USAGE ==="
free -m | grep Mem
df -h / | tail -1
echo ""
echo "=== RECENT ALERTS ==="
tail -3 /var/ossec/logs/alerts/alerts.log 2>/dev/null || echo "No alerts yet"
}
```