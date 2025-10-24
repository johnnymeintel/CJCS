# 04_scripts — Automation and Collection Utilities

This directory contains PowerShell and Bash scripts used to perform baseline assessments, automate detections, and streamline investigations.

### Structure
- **baseline/** — Host-level data collection scripts for Windows and Linux.  
  Example: `APP01-Firewall-Configuration.ps1`, `SIEM01-System-Integrity.sh`
- **detection-tests/** — Scripts to generate repeatable events for rule testing.  
- **utilities/** — General automation tools (e.g., GitHub cleanup, .gitkeep creation, jq filters).

### Purpose
The scripts are written to simulate the automation layer of a real SOC — repeatable, auditable, and environment-agnostic.  
Each script directly supports evidence generation or detection validation.
