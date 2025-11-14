#!/bin/bash
# ==============================================================
#  Cookie Jar Cloud Solutions (CJCS)
#  SIEM01 - Wazuh SIEM
# --------------------------------------------------------------
#  Baseline Date : 2025-10-23
#  Author        : Johnny Meintel
#  Version       : 1.0
#  Environment   : Linux / Ubuntu Server
#  Execution     : sudo bash SIEM01_System_Configuration.sh
# --------------------------------------------------------------
#  Purpose :
#    - Capture comprehensive system configuration and state information
#      for baseline comparison, auditing, and post-launch analysis.
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
#    ./SIEM01_System_Configuration.sh
# ==============================================================

DATE=$(date +%Y-%m-%d)
BASE_DIR="/media/sf_CJCS/Baseline/${DATE}/SIEM01"
mkdir -p "$BASE_DIR"

echo "=== Collecting SIEM01 System Configuration Baseline ==="

# -------------------------------
# Network Interfaces & Routing
# -------------------------------
echo "[*] Capturing network configuration..."
ip addr show > "$BASE_DIR/siem01-network-interfaces.txt"
ip route show > "$BASE_DIR/siem01-routing-table.txt"
cat /etc/resolv.conf > "$BASE_DIR/siem01-dns-config.txt"

# -------------------------------
# Time Synchronization & Chrony
# -------------------------------
echo "[*] Capturing time synchronization details..."
timedatectl status > "$BASE_DIR/siem01-time-sync-status.txt"
chronyc tracking > "$BASE_DIR/siem01-chrony-tracking.txt"
chronyc sources -v > "$BASE_DIR/siem01-chrony-sources.txt"
timedatectl show | grep NTPSynchronized > "$BASE_DIR/siem01-ntp-kernel-flag.txt"
cat /etc/chrony/chrony.conf > "$BASE_DIR/siem01-chrony-conf.txt"

# -------------------------------
# Firewall Status
# -------------------------------
echo "[*] Capturing firewall configuration..."
sudo ufw status verbose > "$BASE_DIR/siem01-firewall-status.txt"

# -------------------------------
# Open Ports
# -------------------------------
echo "[*] Capturing active listening sockets..."
sudo ss -tuln > "$BASE_DIR/siem01-open-ports.txt"

# -------------------------------
# Running Services
# -------------------------------
echo "[*] Listing active services..."
systemctl list-units --type=service --state=running > "$BASE_DIR/siem01-running-services.txt"

# -------------------------------
# Installed Packages
# -------------------------------
echo "[*] Listing installed packages..."
dpkg -l > "$BASE_DIR/siem01-installed-packages.txt"

# -------------------------------
# Host Identity & Uptime
# -------------------------------
echo "[*] Capturing system identity and uptime..."
hostnamectl > "$BASE_DIR/siem01-host-identity.txt"
uptime -p > "$BASE_DIR/siem01-uptime.txt"

# -------------------------------
# Integrity Hashes (Optional)
# -------------------------------
echo "[*] Generating integrity hashes for baseline files..."
sha256sum "$BASE_DIR"/* > "$BASE_DIR/siem01-baseline-hashes.txt"

# -------------------------------
# Completion
# -------------------------------
echo "Baseline collection complete."
echo "All outputs saved to: $BASE_DIR"
