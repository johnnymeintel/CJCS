| Script                                    | Purpose                                                                | Key Evidence Outputs                                                                                                        |
| ----------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **SIEM01_System_Configuration.sh**        | Captures network, firewall, time sync, services, and package inventory | `siem01-network-interfaces.txt`, `siem01-time-sync-status.txt`, `siem01-firewall-status.txt`, `siem01-running-services.txt` |
| **SIEM01_Wazuh_Manager_Configuration.sh** | Exports manager config, rules, decoders, agent list, and API YAML      | `wazuh-ossec.conf`, `wazuh-client-keys.txt`, `wazuh-agent-list.txt`, etc.                                                   |
| **SIEM01_Wazuh_Indexer_Configuration.sh** | Backs up OpenSearch config, templates, and index metadata              | `wazuh-indexer-config.yml`, `wazuh-index-template.json`, `wazuh-indices-status.txt`                                         |
| **SIEM01_Filebeat_Configuration.sh**      | Captures Filebeat→Indexer configuration to verify log shipping         | `filebeat-config.yml`                                                                                                       |
| **SIEM01_Log_Collection.sh**              | Pulls live samples and statistics from logs to confirm flow            | `siem01-syslog-sample.txt`, `siem01-auth-sample.txt`, `wazuh-alert-statistics.txt`                                          |


---

### System Configuration

| Metric                        | Value                                                                                      | Location                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| **Operating System**          | Ubuntu 24.04.3 LTS                                                                         | `lsb_release -d` or `cat /etc/os-release`                                |
| **Hostname**                  | SIEM01                                                                                     | `hostname`                                                               |
| **Kernel**                    | Linux 6.8.0-85-generic                                                                     | `uname -r`                                                               |
| **Uptime**                    | 2 h 57 m                                                                                   | `uptime -p`                                                              |
| **IP Address**                | enp0s3 - 192.168.100.5/24                                                                  | `ip addr show enp0s3`                                                    |
| **NAT**                       | enp0s8 - 10.0.3.15/24                                                                      | `ip addr show enp0s8`                                                    |
| **Default Route**             | enp0s8 - 10.0.3.2 metric 100                                                               | `ip route show default`                                                  |
| **On-link Route**             | enp0s3 - 192.168.100.0/24                                                                  | `ip route show`                                                          |
| **Firewall Status**           | Inactive                                                                                   | `sudo ufw status` or `sudo systemctl status ufw`                         |
| **System Clock Synchronized** | Yes                                                                                        | `timedatectl status`                                                     |
| **NTP Service**               | Active                                                                                     | `systemctl status chronyd`                                               |
| **Stratum**                   | 2                                                                                          | `chronyc tracking`                                                       |
| **Leap Status**               | Normal                                                                                     | `chronyc tracking`                                                       |
| **Chrony Source**             | 192.168.100.10 (DC01)                                                                      | `chronyc sources -v`                                                     |
| **Reach**                     | 377                                                                                        | `chronyc sources`                                                        |
| **Listening Ports**           | 22 (SSH) · 443 (Dashboard) · 55000 (Wazuh API) · 1514/1515 (Manager) · 9200/9300 (Indexer) | `ss -tuln`                                                               |
| **DNS Resolver(s)**           | 127.0.0.53, 127.0.0.54 (local stub)                                                        | `cat /etc/resolv.conf`                                                   |
| **DHCP Client (NAT iface)**   | enp0s8 requesting via UDP 68                                                               | `sudo journalctl -u systemd-networkd \| grep DHCP` or `sudo dhclient -v` |
| **Chrony Local Socket**       | 127.0.0.1:323 (active)                                                                     | `ss -uap \| grep chronyd`                                                |

---

### Wazuh Manager Configuration

| Metric                              | Value                                                                                                                          | Location                                    |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- |
| **Wazuh Version**                   | version=4.14.0 revision=rc2 type=server                                                                                        | `/var/ossec/bin/wazuh-control info`         |
| **API Status**                      | default                                                                                                                        | `/var/ossec/api/configuration/api.yaml`     |
| **Manager Ports**                   | 1515/tcp (server auth) • 1514/tcp (event receiver) • 55000/tcp (API) • 9200/tcp (OpenSearch) • 9300–9400/tcp (indexer cluster) | `ss -tuln`                                  |
| **ossec.conf Validated**            | `wazuh-ossec.conf`                                                                                                             | `/var/ossec/etc/ossec.conf`                 |
| **Agent Count**                     | Active=3                                                                                                                       | `/var/ossec/bin/agent_control -l`           |
| **Local Rules Loaded**              | 1                                                                                                                              | `/var/ossec/etc/rules/local_rules.xml`      |
| **Custom Rule Example (T1110.003)** | `password-spray.xml`                                                                                                           | `/var/ossec/etc/rules/`                     |
| **MITRE ATT&CK Coverage**           | T1110.003                                                                                                                      | `/var/ossec/etc/rules/`                     |
| **Decoders**                        | default=none                                                                                                                   | `/var/ossec/etc/decoders/`                  |
| **client.keys**                     | 3                                                                                                                              | `/var/ossec/etc/client.keys`                |
| **wazuh-api-config.yaml**           | default                                                                                                                        | `/var/ossec/api/configuration/api.yaml`     |
| **Manager Service Status**          | active (running)                                                                                                               | `systemctl status wazuh-manager`            |
| **Rule Count**                      | 3                                                                                                                              | `grep -c "<rule" /var/ossec/etc/rules/*`    |
| **Active Agent IPs**                | ID: 000 (siem01 127.0.0.1)<br>ID: 002 (DC01 192.168.100.10)<br>ID: 003 (APP01 any) <br>ID: 008 (WIN11-MGR1 any)                | `/var/ossec/bin/agent_control -l`           |
| **Backup Files**                    | wazuh-ossec.conf • wazuh-client-keys.txt • wazuh-local-rules.xml • wazuh-api-config.yaml • wazuh-backup-hashes.txt             | `/media/sf_CJCS/Baseline/2025-10-24/SIEM01` |
| **Integrity Manifest**              | `wazuh-backup-hashes.txt`                                                                                                      | `/media/sf_CJCS/Baseline/2025-10-24/SIEM01` |
| **Baseline Script**                 | `SIEM01_Wazuh_Manager_Configuration.sh`                                                                                        | `/media/sf_CJCS/Baseline/2025-10-24/SIEM01` |


---

### Wazuh Indexer Configuration

| Metric                        | Value                                                                       | Observation                                                                            |
| ----------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Node Name**                 | `node-1`                                                                    | Confirms single-node deployment; matches `opensearch.yml`.                             |
| **Cluster Name**              | `wazuh-cluster`                                                             | Default Wazuh Indexer cluster ID — baseline for drift detection.                       |
| **Cluster UUID**              | `gn5JG787QTS-B6IHSj_WnA`                                                    | Unique cluster identity; changes if cluster rebuilt.                                   |
| **Version**                   | `7.10.2` (`lucene_version 9.12.2`)                                          | Confirms underlying OpenSearch build (Wazuh 4.14 stack).                               |
| **Build Type**                | `deb`                                                                       | Installed via APT package.                                                             |
| **Build Hash**                | `d8904e05b830de4e0d9015e8a0587f8479ff72b`                                   | Version integrity hash; traceable lineage.                                             |
| **Build Date**                | `2025-10-17T12:08:14.556Z`                                                  | Confirms current package generation date.                                              |
| **Wire Compatibility**        | `7.10.0`                                                                    | Minimum supported version for cluster interop.                                         |
| **Tagline**                   | `"The OpenSearch Project: https://opensearch.org/"`                         | Confirms normal API response and security plugin auth.                                 |
| **network.host**              | `0.0.0.0`                                                                   | Listens on all interfaces; allows local and remote connections.                        |
| **path.data / path.logs**     | `/var/lib/wazuh-indexer` / `/var/log/wazuh-indexer`                         | Data and log storage paths.                                                            |
| **TLS Certificates**          | `/etc/wazuh-indexer/certs/wazuh-indexer.pem` + key + CA                     | HTTPS/TLS enabled; local certificate chain validated.                                  |
| **TLS Protocols / Ciphers**   | TLS 1.2 (AES-GCM suites)                                                    | Strong cipher set; modern compatibility.                                               |
| **Hostname Verification**     | `false`                                                                     | Disabled to simplify internal lab TLS trust.                                           |
| **Admin DN / Node DN**        | `CN=admin,…` / `CN=indexer,…`                                               | Certificate DNs for admin auth and node trust.                                         |
| **Security Plugin**           | `enabled` (REST roles: `all_access`, `security_rest_api_access`)            | Confirms OpenSearch security module active.                                            |
| **System Indices Protection** | `true`                                                                      | Protects internal OpenSearch system indices.                                           |
| **Compatibility Override**    | `true`                                                                      | Ensures Filebeat OSS 7.10.2 compatibility.                                             |
| **Template Count**            | `18`                                                                        | 3 global (`wazuh`, `wazuh-agent`, `wazuh-statistics`) + 15 SIEM01 inventory templates. |
| **Template Patterns**         | `wazuh-alerts-*`, `wazuh-monitoring-*`, `wazuh-statistics-*`                | Expected Wazuh templates present; mappings healthy.                                    |
| **Index Health**              | `green`                                                                     | All indices operational and synchronized.                                              |
| **Active Indices**            | Multiple (`wazuh-alerts-4.x`, `wazuh-monitoring`, `wazuh-statistics`, etc.) | Confirms normal ingestion and Syscollector indexing.                                   |
| **Baseline Directory**        | `/media/sf_CJCS/Baseline/10-24-2025/SIEM01/`                                | Location of backed-up configuration and template files.                                |

---

### Log Collection

| Metric / Check                 | Value / Observation                                                                                                                                                                                                                                     | Location / Command                           |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| **Syslog Events Captured**     | 100 lines sampled — systemd and Wazuh startup sequence logged; all services initialized cleanly (`wazuh-manager`, `wazuh-indexer`, `wazuh-logcollector`); no critical warnings.                                                                         | `sudo tail -n 100 /var/log/syslog`           |
| **Auth Log Events Captured**   | 100 lines sampled — valid `sudo` sessions for user `jmeintel`; CRON jobs executed normally; no failed or suspicious logins.                                                                                                                             | `sudo tail -n 100 /var/log/auth.log`         |
| **Wazuh Manager Log Captured** | 100 lines sampled — daemons (`syscheckd`, `analysisd`, `remoted`, `logcollector`, `modulesd`) active; Rootcheck, FIM, SCA, and Vulnerability modules initialized; temporary `IndexerConnector` sync errors self-recovered; total enabled rules: `7068`. | `sudo tail -n 100 /var/ossec/logs/ossec.log` |
| **Alert Statistics / Agents**  | `agent_control -s` output collected — 4 agents reporting (DC01, APP01, MGR1, SIEM01); all synchronized and responding.                                                                                                                                  | `/var/ossec/bin/agent_control -s`            |
| **Alert Engine Status**        | Active — rule engine operational; duplicate rule warning (`100001`) noted; no functional issues.                                                                                                                                                        | Review `wazuh-manager-log-sample.txt`        |
| **Evidence Directory**         | `/media/sf_CJCS/Baseline/10-24-2025/SIEM01/`                                                                                                                                                                                                            | Script variable `$BASE_DIR`                  |
| **Integrity Verification**     | SHA-256 manifest generated (`siem01-logflow-hashes.txt`) validating all exported samples.                                                                                                                                                               | `sha256sum "$BASE_DIR"/*`                    |

---

### Filebeat Configuration

| Setting / Metric                | Value / Observation                                                                                          | Source / How to Verify                                                            |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| **Filebeat Version**            | `7.10.2`                                                                                                     | `filebeat version`                                                                |
| **Configuration File Path**     | `/etc/filebeat/filebeat.yml`                                                                                 | Captured automatically by baseline script                                         |
| **Output Destination**          | `hosts: ["127.0.0.1:9200"]`                                                                                  | Found in `output.elasticsearch.hosts:`                                            |
| **Protocol / SSL/TLS Enabled**  | `https` / `true`                                                                                             | `output.elasticsearch.protocol: https` and `ssl.certificate_authorities:` entries |
| **Certificate Authority Path**  | `/etc/filebeat/certs/root-ca.pem`                                                                            | `ssl.certificate_authorities:` field                                              |
| **Client Certificate / Key**    | `/etc/filebeat/certs/wazuh-server.pem` / `/etc/filebeat/certs/wazuh-server-key.pem`                          | `ssl.certificate:` and `ssl.key:` fields                                          |
| **Enabled Modules**             | `wazuh` module: `alerts` enabled, `archives` disabled                                                        | `filebeat.modules:` block                                                         |
| **Template Settings**           | JSON template `/etc/filebeat/wazuh-template.json` (name: `wazuh`); ILM disabled (`setup.ilm.enabled: false`) | `setup.template.json.*` and `setup.ilm.*` sections                                |
| **Logging Level / Destination** | Level: `info` → `/var/log/filebeat/filebeat` (7 files retained, permissions `0644`)                          | `logging.level:` and `logging.files:` entries                                     |
| **Logging Metrics**             | Disabled (`logging.metrics.enabled: false`)                                                                  | `logging.metrics.enabled:` field                                                  |
| **Seccomp Policy**              | Default action: `allow`; syscall exception: `rseq`                                                           | `seccomp:` block                                                                  |
| **Service Status**              | `active (running)`                                                                                           | `systemctl status filebeat`                                                       |
| **Pipeline Verification**       | Logs successfully ingested to `wazuh-alerts-*` index via HTTPS                                               | `curl -sk -u admin:<password> "https://localhost:9200/_cat/indices?v"`            |
| **Integrity Verification**      | SHA-256 manifest generated (`filebeat-hash.txt`) validating configuration integrity                          | `sha256sum "$BASE_DIR/filebeat-config.yml"`                                       |
| **Evidence Directory**          | `/media/sf_CJCS/Baseline/10-24-2025/SIEM01/`                                                                 | Script variable `$BASE_DIR`                                                       |
