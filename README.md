# Cookie Jar Cloud Solutions (CJCS) - part of the Cybersecurity Roleplay Challenge

## Project Overview

This homelab project documents a complete security transformation journey from SaaS startup to SOC 2 compliance readiness, as part of the "Cybersecurity Roleplay Challenge". The challenge is a response to the current market dynamic in which entry-level cybersecurity candidates may be expected to possess experience they do not have, and skills which are beyond what is commonly described as "entry-level". The truth is, cybersecurity is not an entry-level field. As a computer scientist and security enthusiast, I have tasked myself with simulating the business impact of cybersecurity in addition to the technical implementation, in an effort to gain a comprehensive understanding and simulate the "experience" required for an entry level cybersecurity role. Every PowerShell script, every error message, every IP address - simulates real-world business impact within the CJCS narrative. 

**Business Context:** Cookie Jar Cloud Solutions is a simulated mid-market restaurant SaaS company ($12.8M ARR, 67 employees) facing the reality that many growing businesses encounter: rapid expansion with no cybersecurity program. CJCS provides inventory management and cost optimization software to restaurant chains across the Pacific Northwest. After a competitor breach exposed 200+ restaurants' data and customer security questionnaires started blocking sales deals, leadership finally allocated budget for cybersecurity infrastructure. 

**CJCS Product Offering:** 
```
Under Construction
```

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

### Phase 1: Baseline Assessment (In Progress)
- **Security Posture:** Complete visibility gap - no monitoring, flat network, shared admin passwords
- **Business Impact:** Failed security questionnaires preventing adequate customer relationship growth 
- **Risk Analysis:** Full domain admin compromise possible within minutes of initial access given current security configuration 

### Phase 2: SIEM Implementation 🚧
- **Technology:** Wazuh manager with integrated ELK stack for log analysis and visualization
- **Scope:** Windows event logs, system monitoring, and basic threat detection rules
- **Challenge:** Balancing detection coverage with alert fatigue for a small team

### Phase 3: Detection Engineering (Planned)
- **MITRE ATT&CK Mapping:** Building detection rules for tactics most relevant to SMB environments
- **Custom Rules:** Focusing on credential access, lateral movement, and data exfiltration scenarios
- **Tuning:** Reducing false positives while maintaining sensitivity to actual threats

### Phase 4: Incident Response (Planned)
- **Playbooks:** Documented procedures for common incident types in restaurant industry
- **Automation:** Basic SOAR capabilities for initial triage and containment
- **Business Integration:** Executive reporting and customer communication templates

## Repository Structure

```
Under Construction
```

## Real-World Applications

This lab environment simulates security challenges commonly faced by growing SMBs:

- **Resource Constraints:** Implementing enterprise-grade security with limited budget and staff
- **Compliance Pressure:** Meeting customer security requirements while maintaining operations  
- **Alert Fatigue:** Balancing comprehensive monitoring with manageable alert volumes
- **Business Integration:** Communicating security value to non-technical stakeholders

## Progress Tracking

- [x] Initial infrastructure deployment
- [ ] Baseline security assessment 
- [ ] Wazuh SIEM installation and configuration
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
*This project represents practical, hands-on experience with cybersecurity implementation, all CJCS company data is entirely fictitious*
