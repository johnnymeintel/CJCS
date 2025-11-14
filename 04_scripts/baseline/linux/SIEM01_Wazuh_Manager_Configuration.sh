#!/bin/bash
# ==============================================================
#  Cookie Jar Cloud Solutions (CJCS)
#  SIEM01 - Wazuh Manager Configuration Baseline
# --------------------------------------------------------------
#  Baseline Date : $(date +%Y-%m-%d)
#  Author        : Johnny Meintel
#  Version       : 1.1
#  Environment   : Linux / Ubuntu Server
#  Execution     : sudo bash SIEM01_Wazuh_Manager_Configuration.sh
# --------------------------------------------------------------
#  Purpose :
#    - Back up Wazuh Manager configuration files, rule sets,
#      and agent data to preserve SIEM integrity prior to
#      major updates, tuning changes, or audits.
#
#  Notes :
#    - Ensure sufficient permissions before execution.
#    - Output directory structure: /media/sf_CJCS/Baseline/<date>/<host>/
#    - Recommended to run before rule tuning or Wazuh upgrades.
#
#  Change Log :
#    2025-10-23  Johnny Meintel  Launch
# --------------------------------------------------------------
#  Example :
#    ./SIEM01_Wazuh_Manager_Configuration.sh
# ==============================================================

# --------------------------------------------------------------
# 0. Initialization
# --------------------------------------------------------------
DATE=$(date +%Y-%m-%d)
BASE_DIR="/media/sf_CJCS/Baseline/${DATE}/SIEM01"
mkdir -p "$BASE_DIR"

echo "=== Starting Wazuh Manager Configuration Backup ==="
echo "Backup target: $BASE_DIR"
echo ""

# --------------------------------------------------------------
# 1. Core Configuration Files
# --------------------------------------------------------------
echo "[*] Backing up core configuration files..."
if [ -f /var/ossec/etc/ossec.conf ]; then
    sudo cp /var/ossec/etc/ossec.conf "$BASE_DIR/wazuh-ossec.conf"
    echo "✓ ossec.conf backed up"
else
    echo "⚠ ossec.conf not found!"
fi

if [ -f /var/ossec/etc/client.keys ]; then
    sudo cp /var/ossec/etc/client.keys "$BASE_DIR/wazuh-client-keys.txt"
    echo "✓ client.keys backed up"
else
    echo "⚠ client.keys not found!"
fi
echo ""

# --------------------------------------------------------------
# 2. Local Rules and Decoders
# --------------------------------------------------------------
echo "[*] Capturing local customization files..."
if [ -f /var/ossec/etc/rules/local_rules.xml ]; then
    sudo cp /var/ossec/etc/rules/local_rules.xml "$BASE_DIR/wazuh-local-rules.xml"
    echo "✓ local_rules.xml backed up"
else
    echo "⚠ local_rules.xml not found (no custom rules yet)"
fi

if [ -f /var/ossec/etc/decoders/local_decoder.xml ]; then
    sudo cp /var/ossec/etc/decoders/local_decoder.xml "$BASE_DIR/wazuh-local-decoders.xml"
    echo "✓ local_decoder.xml backed up"
else
    echo "⚠ local_decoder.xml not found (no custom decoders yet)"
fi
echo ""

# --------------------------------------------------------------
# 3. Custom Rule Examples
# --------------------------------------------------------------
echo "[*] Checking for password spray detection rule..."
if [ -f /var/ossec/etc/rules/password-spray.xml ]; then
    sudo cp /var/ossec/etc/rules/password-spray.xml "$BASE_DIR/wazuh-password-spray-rule.xml"
    echo "✓ password-spray.xml backed up"
else
    echo "⚠ password-spray.xml not found (rule not deployed)"
fi
echo ""

# --------------------------------------------------------------
# 4. Agent Configuration & Status
# --------------------------------------------------------------
echo "[*] Exporting agent list..."
if command -v /var/ossec/bin/agent_control >/dev/null 2>&1; then
    sudo /var/ossec/bin/agent_control -l > "$BASE_DIR/wazuh-agent-list.txt"
    echo "✓ agent list exported"
else
    echo "⚠ agent_control not found — Wazuh may not be running"
fi
echo ""

# --------------------------------------------------------------
# 5. Wazuh API Configuration
# --------------------------------------------------------------
echo "[*] Backing up Wazuh API configuration..."
if [ -f /var/ossec/api/configuration/api.yaml ]; then
    sudo cp /var/ossec/api/configuration/api.yaml "$BASE_DIR/wazuh-api-config.yaml"
    echo "✓ api.yaml backed up"
else
    echo "⚠ api.yaml not found (API may not be configured yet)"
fi
echo ""

# --------------------------------------------------------------
# 6. Integrity Hash Manifest
# --------------------------------------------------------------
echo "[*] Generating SHA256 hash manifest..."
echo "Generated on: $(date)" > "$BASE_DIR/wazuh-backup-hashes.txt"
sha256sum "$BASE_DIR"/wazuh-* >> "$BASE_DIR/wazuh-backup-hashes.txt"
echo "✓ Integrity manifest created"

# --------------------------------------------------------------
# 7. Completion
# --------------------------------------------------------------
echo ""
echo "=== ✓ Wazuh Manager Backup Complete ==="
echo "All files saved to: $BASE_DIR"
echo "Integrity manifest: wazuh-backup-hashes.txt"
exit 0