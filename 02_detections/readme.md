# 02_detections — Detection Engineering Rules

This folder houses all custom detection logic developed for the CJCS lab.  
Rules are written for the Wazuh SIEM and follow MITRE ATT&CK mapping conventions.

### Structure
- **windows/** — XML rules covering credential access, PowerShell abuse, and brute-force detection.
- **linux/** — Placeholder for future Syslog and system integrity detections.

### Example Rules
- **password-spray.xml** — Detects multiple failed logons (Event ID 4625) within a short timeframe.  
- **credential-dumping.xml** — Detects LSASS memory access (T1003.001).  
- **malicious-powershell.xml** — Identifies suspicious PowerShell activity with encoded or obfuscated commands.

### Validation
Each rule is linked to its corresponding simulation under `/03_attacks/`.  
Successful triggers are documented under `/01_docs/Investigations/`.

**Goal:** Demonstrate an understanding of noise reduction, correlation logic, and MITRE-aligned rule design.
