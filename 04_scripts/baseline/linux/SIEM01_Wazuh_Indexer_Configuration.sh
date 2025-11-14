#!/bin/bash
# ==============================================================
#  Cookie Jar Cloud Solutions (CJCS)
#  SIEM01 - Wazuh SIEM
# --------------------------------------------------------------
#  Baseline Date : $(date +%Y-%m-%d)
#  Author        : Johnny Meintel
#  Version       : 1.0
#  Environment   : Linux / Ubuntu Server
#  Execution     : sudo bash SIEM01_Wazuh_Indexer_Configuration.sh
# --------------------------------------------------------------
#  Purpose :
#    - Capture and archive core Wazuh Indexer (OpenSearch) configurations,
#      templates, and index metadata to document data storage state and
#      support configuration validation and forensic review.
#
#  Notes :
#    - Ensure sufficient permissions before execution.
#    - Output directory structure: /media/sf_CJCS/Baseline/<date>/<host>/ 
#    - Recommended to run post-reboot or pre-deployment for clean baselines.
#
#  Change Log :
#    2025-10-23  Johnny Meintel  Launch
# --------------------------------------------------------------
#  Example :
#    ./SIEM01_Wazuh_Indexer_Configuration.sh
# ==============================================================

# Define dynamic base directory with date
DATE=$(date +%Y-%m-%d)
BASE_DIR="/media/sf_CJCS/Baseline/${DATE}/SIEM01"
mkdir -p "$BASE_DIR"

# --------------------------------------------------------------
# 1. OpenSearch / Indexer Configuration
# --------------------------------------------------------------
echo "[*] Backing up OpenSearch configuration..."
sudo cp /etc/wazuh-indexer/opensearch.yml "$BASE_DIR/wazuh-indexer-config.yml"
echo "✓ OpenSearch configuration backed up"

# --------------------------------------------------------------
# 2. Index Templates and Mappings
# --------------------------------------------------------------
echo "[*] Exporting index templates..."
curl -sk -u admin:YOURPASSWORDHERE "https://localhost:9200/_cat/templates?v" > "$BASE_DIR/wazuh-index-template.json"
echo "✓ Index templates exported"

# --------------------------------------------------------------
# 3. Current Indices and Their Status
# --------------------------------------------------------------
echo "[*] Exporting current indices status..."
curl -s -u admin:YOURPASSWORDHERE -XGET "https://localhost:9200/_cat/indices?v" > "$BASE_DIR/wazuh-indices-status.txt"
echo "✓ Indices status exported"

# --------------------------------------------------------------
# 4. Integrity Hash Generation
# --------------------------------------------------------------
echo "[*] Generating integrity hash for backup files..."
sha256sum "$BASE_DIR/wazuh-indexer-config.yml" "$BASE_DIR/wazuh-index-template.json" "$BASE_DIR/wazuh-indices-status.txt" > "$BASE_DIR/wazuh-indexer-hashes.txt"
echo "✓ Integrity hash generated"

# --------------------------------------------------------------
# 5. Completion
# --------------------------------------------------------------
echo ""
echo "=== ✓ Wazuh Indexer Baseline Complete ==="
echo "All files saved to: $BASE_DIR"
