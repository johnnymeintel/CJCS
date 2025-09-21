# Cookie Jar Cloud Solutions (CJCS) - SOC Implementation Lab

## Project Overview

Cookie Jar Cloud Solutions is a simulated mid-market restaurant SaaS company ($12.8M ARR, 67 employees) facing the reality that many growing businesses encounter: rapid expansion with no cybersecurity program. This homelab project documents the complete security transformation journey from "we don't even know what we don't know" to SOC 2 compliance readiness.

**Business Context:** CJCS provides inventory management and cost optimization software to restaurant chains across the Pacific Northwest. After a competitor breach exposed 200+ restaurants' data and customer security questionnaires started blocking sales deals, leadership finally allocated budget for cybersecurity infrastructure.

## Architecture Overview

### Network Configuration
- **Host-only Network:** vboxnet0 (192.168.100.0/24)
- **Gateway:** 192.168.100.1  
- **DNS:** 192.168.100.10 (DC01)

### Current Infrastructure

| VM Name    | Role                     | IP Address       | Specs        | Status |
|------------|--------------------------|------------------|--------------|--------|
| DC01       | Domain Controller        | 192.168.100.10   | 2 vCPU, 4GB  | ✅ Active |
| APP01      | Application Server       | 192.168.100.20   | 4 vCPU, 8GB  | ✅ Active |
| WIN11-MGR1 | Manager Workstation      | 192.168.100.101  | 2 vCPU, 4GB  | ✅ Active |
| SIEM01     | Wazuh SIEM + ELK Stack   | 192.168.100.5    | 4 vCPU, 8GB  | ✅ Active |

**Total Resources:** 12 vCPU, 24 GB RAM, 360 GB storage

## Project Phases

### Phase 1: Baseline Assessment ✅
- **Security Posture:** Complete visibility gap - no monitoring, flat network, shared admin passwords
- **Business Impact:** Failed security questionnaires blocking $300K in pipeline deals
- **Risk Analysis:** Full domain admin compromise possible within minutes of initial access

### Phase 2: SIEM Implementation 🚧
- **Technology:** Wazuh manager with integrated ELK stack for log analysis and visualization
- **Scope:** Windows event logs, system monitoring, and basic threat detection rules
- **Challenge:** Balancing detection coverage with alert fatigue for a small team

### Phase 3: Detection Engineering (In Progress)
- **MITRE ATT&CK Mapping:** Building detection rules for tactics most relevant to SMB environments
- **Custom Rules:** Focusing on credential access, lateral movement, and data exfiltration scenarios
- **Tuning:** Reducing false positives while maintaining sensitivity to actual threats

### Phase 4: Incident Response (Planned)
- **Playbooks:** Documented procedures for common incident types in restaurant industry
- **Automation:** Basic SOAR capabilities for initial triage and containment
- **Business Integration:** Executive reporting and customer communication templates

## Key Learning Objectives

### Technical Skills
- **SIEM Administration:** Wazuh deployment, configuration, and maintenance
- **Detection Engineering:** Writing and tuning rules based on real attack patterns  
- **Windows Security:** Advanced event log analysis and PowerShell forensics
- **Linux Administration:** Ubuntu server management and ELK stack operations
- **Network Security:** Segmentation planning and monitoring implementation

### Business Skills
- **Risk Communication:** Translating technical findings into business impact
- **Compliance Mapping:** SOC 2 requirements and audit preparation
- **Resource Planning:** Security budget allocation and staffing recommendations
- **Vendor Management:** Security tool evaluation and procurement processes

## Repository Structure

```
cjcs/
├── docs/
│   ├── business-context/          # Company background and threat landscape
│   ├── architecture/              # Network diagrams and system specifications  
│   ├── security-assessments/      # Baseline findings and risk analysis
│   └── compliance/                # SOC 2 mapping and audit preparation
├── configs/
│   ├── wazuh/                     # SIEM configuration files and custom rules
│   ├── windows/                   # Group policy and hardening templates
│   └── network/                   # VirtualBox network configuration
├── playbooks/
│   ├── incident-response/         # Step-by-step procedures for common scenarios
│   ├── threat-hunting/            # Manual investigation techniques
│   └── business-continuity/       # Disaster recovery and backup procedures
└── scripts/
    ├── deployment/                # Automated VM provisioning and configuration
    ├── monitoring/                # Health checks and maintenance automation
    └── testing/                   # Attack simulation and detection validation
```

## Quick Start

### Prerequisites
- VirtualBox 7.0+ with Extension Pack
- 32 GB RAM minimum (64 GB recommended)
- 500 GB available storage
- Windows Server 2022 and Ubuntu 22.04 ISOs

### Basic Setup
1. **Network Configuration**
   ```bash
   # Create host-only network
   VBoxManage hostonlyif create
   VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.100.1 --netmask 255.255.255.0
   ```

2. **Domain Controller (DC01)**
   - Install Windows Server 2022 with Desktop Experience
   - Configure Active Directory Domain Services
   - Set up DNS and DHCP services
   - Create domain: `cjcs.local`

3. **SIEM Server (SIEM01)**
   - Install Ubuntu Server 22.04
   - Deploy Wazuh all-in-one installation
   - Configure Windows agent deployment
   - Import custom detection rules

4. **Application Server (APP01)**
   - Join to domain and configure IIS
   - Install Wazuh agent and configure log forwarding
   - Deploy sample restaurant management application

## Real-World Applications

This lab environment simulates security challenges commonly faced by growing SMBs:

- **Resource Constraints:** Implementing enterprise-grade security with limited budget and staff
- **Compliance Pressure:** Meeting customer security requirements while maintaining operations  
- **Alert Fatigue:** Balancing comprehensive monitoring with manageable alert volumes
- **Business Integration:** Communicating security value to non-technical stakeholders

## Progress Tracking

- [x] Initial infrastructure deployment
- [x] Baseline security assessment 
- [x] Wazuh SIEM installation and configuration
- [ ] Custom detection rule development
- [ ] Incident response playbook creation
- [ ] SOC 2 compliance gap analysis
- [ ] Executive dashboard and reporting
- [ ] Disaster recovery testing

## Contact

**Johnny Meintel**  
Cybersecurity Professional | Seattle, WA  
📧 johnnymeintel@gmail.com  
🔗 [LinkedIn Profile](https://linkedin.com/in/johnnymeintel)

---
*This project represents practical, hands-on experience with cybersecurity implementation in resource-constrained environments. All scenarios are based on real challenges faced by SMBs in their security maturity journey.*
