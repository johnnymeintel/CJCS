#!/bin/bash
# ==============================================================
#  Cookie Jar Cloud Solutions (CJCS)
#  SIEM01 - Log Flow & Alert Verification
# --------------------------------------------------------------
#  Baseline Date : 2025-10-23
#  Author        : Johnny Meintel
#  Version       : 1.0
#  Environment   : Linux / Ubuntu Server
#  Execution     : sudo bash SIEM01_LogFlow_Verification.sh
# --------------------------------------------------------------
#  Purpose :
#    - Validate that system and security logs are actively flowing
#      into the SIEM environment and confirm alert generation
#      through Wazuh agent statistics.
#
#  Notes :
#    - Run post-deployment or after rule updates to confirm log flow.
#    - Requires Wazuh Manager service to be active.
#    - Output directory structure: /media/sf_CJCS/Baseline/<date>/<host>/
#
#  Change Log :
#    2025-10-23  Johnny Meintel  Launch
# --------------------------------------------------------------
#  Example :
#    ./SIEM01_LogFlow_Verification.sh
# ==============================================================

DATE=$(date +%Y-%m-%d)
BASE_DIR="/media/sf_CJCS/Baseline/${DATE}/SIEM01"
mkdir -p "$BASE_DIR"

echo "=== Collecting SIEM01 Log Flow and Alert Verification Baseline ==="

# --------------------------------------------------------------
# 1. System Log Samples
# --------------------------------------------------------------
echo "[*] Capturing log samples to confirm flow..."
sudo tail -n 100 /var/log/syslog > "$BASE_DIR/siem01-syslog-sample.txt"
sudo tail -n 100 /var/log/auth.log > "$BASE_DIR/siem01-auth-sample.txt"
sudo tail -n 100 /var/ossec/logs/ossec.log > "$BASE_DIR/wazuh-manager-log-sample.txt"
echo "✓ Log samples captured (syslog, auth.log, ossec.log)"

# --------------------------------------------------------------
# 2. Wazuh Alert Statistics
# --------------------------------------------------------------
echo "[*] Capturing Wazuh alert statistics..."
if command -v /var/ossec/bin/agent_control >/dev/null 2>&1; then
    sudo /var/ossec/bin/agent_control -s > "$BASE_DIR/wazuh-alert-statistics.txt"
    echo "✓ Wazuh alert statistics exported"
else
    echo "⚠ agent_control not found — Wazuh Manager may not be running"
fi

# --------------------------------------------------------------
# 3. Integrity Hash Manifest
# --------------------------------------------------------------
echo "[*] Generating integrity hash manifest..."
sha256sum "$BASE_DIR"/* > "$BASE_DIR/siem01-logflow-hashes.txt"

# --------------------------------------------------------------
# 4. Completion
# --------------------------------------------------------------
echo ""
echo "=== ✓ Log Flow & Alert Verification Complete ==="
echo "All outputs saved to: $BASE_DIR"
