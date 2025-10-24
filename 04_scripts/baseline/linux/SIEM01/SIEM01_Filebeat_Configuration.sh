#!/bin/bash
# ==============================================================
#  Cookie Jar Cloud Solutions (CJCS)
#  SIEM01 - Filebeat Configuration Baseline
# --------------------------------------------------------------
#  Baseline Date : 2025-10-23
#  Author        : Johnny Meintel
#  Version       : 1.0
#  Environment   : Linux / Ubuntu Server
#  Execution     : sudo bash SIEM01_Filebeat_Configuration.sh
# --------------------------------------------------------------
#  Purpose :
#    - Capture the active Filebeat configuration used to ship
#      Wazuh and system logs to the Indexer for ingestion.
#      Establishes configuration control for log transport.
#
#  Notes :
#    - Run after Filebeat or Wazuh upgrades to validate pipeline.
#    - Output directory structure: /media/sf_CJCS/Baseline/<date>/<host>/
#    - Recommended to verify SSL/TLS, output hosts, and module paths.
#
#  Change Log :
#    2025-10-23  Johnny Meintel  Launch
# --------------------------------------------------------------
#  Example :
#    ./SIEM01_Filebeat_Configuration.sh
# ==============================================================

DATE=$(date +%Y-%m-%d)
BASE_DIR="/media/sf_CJCS/Baseline/${DATE}/SIEM01"
mkdir -p "$BASE_DIR"

echo "=== Capturing SIEM01 Filebeat Configuration Baseline ==="

# --------------------------------------------------------------
# 1. Capture Filebeat Configuration
# --------------------------------------------------------------
echo "[*] Backing up Filebeat configuration..."
if [ -f /etc/filebeat/filebeat.yml ]; then
    sudo cp /etc/filebeat/filebeat.yml "$BASE_DIR/filebeat-config.yml"
    echo "✓ Filebeat configuration exported"
else
    echo "⚠ filebeat.yml not found — Filebeat may not be installed or configured"
fi

# --------------------------------------------------------------
# 2. Generate Integrity Hash
# --------------------------------------------------------------
echo "[*] Generating integrity hash..."
sha256sum "$BASE_DIR/filebeat-config.yml" > "$BASE_DIR/filebeat-hash.txt"

# --------------------------------------------------------------
# 3. Completion
# --------------------------------------------------------------
echo ""
echo "=== ✓ Filebeat Configuration Baseline Complete ==="
echo "All outputs saved to: $BASE_DIR"
