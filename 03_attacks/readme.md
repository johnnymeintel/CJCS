# 03_attacks — Adversarial Simulation and Validation

This directory contains proof-of-concept attack simulations used to validate detection coverage.  
Each subfolder replicates a realistic adversarial technique mapped to MITRE ATT&CK.

### Structure
- **password_spray/** — Simulates repeated authentication failures to test brute-force detection.  
- **lsass_dump/** — Simulates credential dumping with tools like ProcDump or Mimikatz.  
- **phishing_lab/** — Tests email spoofing and DMARC validation logic.

### Usage
Each subfolder includes:
1. **Attack Objective** — The behavior being simulated.  
2. **Execution Commands** — PowerShell or Bash commands to reproduce the test.  
3. **Expected Detection** — Which rule (and rule ID) should fire.  
4. **Validation Artifacts** — Logs and screenshots stored under `/06_evidence/`.

**Purpose:** This folder bridges red and blue — validating that custom rules are functional, tuned, and defensible.
