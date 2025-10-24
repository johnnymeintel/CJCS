# Cookie Jar Cloud Solutions (CJCS)

## Project Overview

**Cookie Jar Cloud Solutions (CJCS)** is a simulated mid-market SaaS company used to demonstrate a complete cybersecurity transformation — from zero visibility to SOC 2 readiness.  
This repository documents every stage of that evolution: baseline security assessment, SIEM deployment, custom detection engineering, and incident-response development.

Every configuration, script, and investigation is treated as production evidence for a fictional business operating under real compliance pressure. The objective is to simulate both the technical execution _and_ the business reasoning required of an entry-level SOC or IR analyst.

**CJCS Product Offering:**

```
Under Construction
```

---

## Architecture Overview

### Network Configuration

- **Host-only Network:** vboxnet0 (192.168.100.0/24)
    
- **Gateway:** 192.168.100.1
    
- **DNS:** 192.168.100.10 (DC01)
    

### Virtual Infrastructure

|VM Name|Role|IP Address|Specs|Status|
|---|---|---|---|---|
|DC01|Domain Controller (AD + DNS + DHCP)|192.168.100.10|2 vCPU / 4 GB|✅ Active|
|APP01|IIS + PostgreSQL App Server|192.168.100.20|4 vCPU / 8 GB|✅ Active|
|WIN11-MGR1|Executive Workstation|192.168.100.101|2 vCPU / 4 GB|✅ Active|
|SIEM01|Wazuh Manager + ELK Stack|192.168.100.5|4 vCPU / 8 GB|✅ Active|

**Total:** 12 vCPU / 24 GB RAM / 360 GB storage

---

## Project Phases

### **Phase 1 – Baseline Assessment (✅ Complete)**

- **Finding:** Flat network, shared credentials, no monitoring.
    
- **Impact:** Failed customer security questionnaires blocking new deals.
    
- **Risk:** Domain-admin compromise feasible within minutes of intrusion.
    

### **Phase 2 – SIEM Implementation (In Progress)**

- **Platform:** Wazuh Manager + OpenSearch + Dashboard.
    
- **Scope:** Windows Event Logs / Linux Syslogs / Agent Telemetry.
    
- **Goal:** Visibility and alerting without alert fatigue.
    

### **Phase 3 – Detection Engineering (In Progress)**

- **MITRE ATT&CK:** Focus on T1110 (Brute Force), T1003 (Credential Access), T1059 (PowerShell).
    
- **Deliverables:** Custom Wazuh rules for password spray, malicious PowerShell, and LSASS memory access.
    
- **Outcome:** High-fidelity detections mapped to validated attack scenarios.
    

### **Phase 4 – Incident Response (Planned)**

- **Playbooks:** Containment and eradication flows for common SMB attack patterns.
    
- **Automation:** Lightweight SOAR actions for triage and ticketing.
    
- **Integration:** Executive reporting aligned to NIST SP 800-61 r2.
    

---

## Key Deliverables

|Deliverable|Description|Location|
|---|---|---|
|**Baseline Assessments**|Complete system security posture documentation|`/docs/baseline-assessments/`|
|**Detection Engineering**|Custom Wazuh rules mapped to MITRE ATT&CK|`/detections/windows/`|
|**Attack Simulations**|Validation scripts for each detection scenario|`/attacks/`|
|**Investigations**|Step-by-step incident analyses with evidence and findings|`/docs/investigations/`|
|**Scripts**|Automated baseline and collection modules for Windows/Linux|`/scripts/baseline/`|
|**Incident Playbooks**|Response workflows and communication templates|`/playbooks/incident-response/`|

---

## Repository Structure

```
CJCS/
├── 📄 README.md
│
├── 📁 detections/                      # Detection rules (XML / Sigma / MITRE mapped)
│   └── 📁 windows/
│       ├── password-spray.xml
│       ├── credential-dumping.xml
│       └── malicious-powershell.xml
│
├── 📁 attacks/                         # Detection validation and simulation scripts
│   ├── password-spray/
│   ├── lsass-dump/
│   └── phishing-lab/
│
├── 📁 docs/                            # Documentation and evidence
│   ├── baseline-assessments/           # Raw host outputs and baselines
│   ├── investigations/                 # Sysmon / 4625 / LSASS case studies
│   ├── strategy.md                     # CJCS business + security alignment
│   └── company-profile.md
│
├── 📁 scripts/                         # Assessment + automation tooling
│   └── baseline/
│       ├── APP01/
│       ├── DC01/
│       ├── MGR1/
│       └── SIEM01/
│
├── 📁 playbooks/                       # Incident response + operational workflows
│   └── incident-response/
│
└── 📁 references/                      # Cheat sheets and supporting material
    └── Wazuh-Cheat-Sheet.md
```

---

## Real-World Applications

This environment mirrors challenges common to fast-growing SMBs:

- **Resource Constraints:** Implementing enterprise-grade security on a budget.
    
- **Compliance Pressure:** Achieving SOC 2 and customer trust without downtime.
    
- **Alert Fatigue:** Balancing signal vs. noise for a small operations team.
    
- **Business Integration:** Translating technical risk into executive language.
    

---

## Lessons Learned

- **Time synchronization** is the first hidden failure mode in any SIEM deployment.
    
- **Detection quality beats quantity:** one tuned rule > ten noisy ones.
    
- **Documentation is defense:** evidence without context is just data.
    
- **Iteration matters:** each baseline → rule → attack → alert loop improves fidelity.
    

---

## Progress Tracking

-  Infrastructure deployed
    
-  Baseline security assessments
    
-  Wazuh SIEM installation and agent integration
    
-  Custom detection rules (extended)
    
-  Incident response playbooks
    
-  SOC 2 compliance gap analysis
    
-  Executive dashboards + reporting
    
-  Disaster recovery testing
    

---

## References and Frameworks

- **MITRE ATT&CK**
    
- **NIST SP 800-61 r2:** Incident Response Lifecycle model
    
- **SOC 2 Trust Service Criteria:** Security · Availability · Confidentiality
    

---

## Contact

**Johnny Meintel**  
Cybersecurity Professional · Seattle, WA  
📧 [johnnymeintel@gmail.com](mailto:johnnymeintel@gmail.com)  
🔗 [LinkedIn](https://linkedin.com/in/johnnymeintel)

---

_All CJCS data and incidents are entirely fictitious and used for educational, non-commercial purposes._