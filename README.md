# Dual-Telemetry Threat Detection Pipeline & Elastic SIEM Lab

## Executive Summary

This project documents the end-to-end build of a security telemetry pipeline integrating host-level process auditing and network intrusion detection into Elastic Cloud SIEM. Using an Ubuntu VM monitored by Elastic Agent, Sysmon for Linux, system authentication logging (`auth.log`), and Suricata NIDS, threat activity was simulated with Nmap and Hydra to validate real-time ingestion, ECS parsing, and automated threshold detection alerting — from initial environment setup through a confirmed, triggered high-severity alert.

The build was not frictionless, and that's intentional to document: package lock conflicts, a missing CD-ROM mount, a pivot from Snort to Suricata, an interface-binding misconfiguration, and a Kibana data-view mismatch all had to be diagnosed and resolved along the way. Each is captured below as part of the process, not edited out.

---

## Technical Architecture & Telemetry Sources

* **Endpoint / Host:** Ubuntu Linux VM (VirtualBox)
* **SIEM / Management:** Elastic Cloud (Kibana, deployment version 9.4.4, GCP us-central1)
* **Log Shipper:** Elastic Agent (Fleet-managed)
* **Host Telemetry:** Sysmon for Linux (process creation, network connections, file creation) & `/var/log/auth.log`
* **Network Telemetry:** Suricata NIDS (`suricata.eve` JSON logs)

| Telemetry Type | Source / Module | Description | ECS / Field Mapping |
| :--- | :--- | :--- | :--- |
| **Host Auth** | `system.auth` | SSH authentication & PAM session logs | `event.action: ssh_login` |
| **Host Process** | Sysmon for Linux | Process execution, network connections, file creation | `process.executable` |
| **Network Flow** | `suricata.eve` | Suricata signatures, flow data, protocol alerts | `data_stream.dataset: suricata-eve` |

![Elastic Cloud Dashboard](05-elastic-cloud-dashboard.png)
![Kibana Security Overview](06-kibana-security-overview.png)

---

## Phase 0: Environment Setup & Troubleshooting

Before any telemetry could flow, the base Ubuntu VM required several fixes:

* **APT dpkg lock conflict** — package installs initially failed with `Could not get lock /var/lib/dpkg/lock-frontend`. Resolved by clearing the stale lock files and retrying `apt-get update`.

![APT Lock Troubleshooting](01-apt-lock-troubleshooting.png)

* **DKMS dependency install** — installing DKMS surfaced a VirtualBox Guest Additions CD-ROM mount failure (`no medium found on /dev/sr0`). Diagnosed via `dmesg` and resolved by re-attaching the Guest Additions ISO in VirtualBox before mounting.

![DKMS Dependency Install](02-dkms-dependency-install.png)
![VBox CD-ROM Mount Check](03-vbox-cdrom-mount-check.png)

* **Elastic Agent enrollment syntax error** — the first install attempt using placeholder values (`<YOUR_FLEET_SERVER_URL>`, `<YOUR_ENROLLMENT_TOKEN>`) failed with a bash syntax error, since the values hadn't been substituted with real Fleet-generated credentials.

![Agent CLI Syntax Error](04-agent-cli-syntax-error.png)

---

## Phase 1: Elastic Agent & Fleet Enrollment

Fleet enrollment tokens were generated from **Fleet → Enrollment tokens**:

![Fleet Tokens Menu](07-fleet-tokens-menu.png)

With the environment stable, the Elastic Agent was downloaded and installed with the real Fleet Server URL and enrollment token:

\`\`\`bash
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.4-linux-x86_64.tar.gz
tar xzvf elastic-agent-9.4.4-linux-x86_64.tar.gz
cd elastic-agent-9.4.4-linux-x86_64
sudo ./elastic-agent install --url=<FLEET_SERVER_URL> --enrollment-token=<ENROLLMENT_TOKEN>
\`\`\`

![Elastic Agent Installation](08-elastic-agent-installation.png)
![Terminal Agent Installation Success](10-terminal-agent-installation-success.png)

Enrollment succeeded and Fleet confirmed both **agent enrollment** and **incoming data** within minutes.

![Agent Enrolled Status](09-kibana-agent-enrolled-status.png)
![Fleet Incoming Data Verified](11-fleet-incoming-data-verified.png)

---

## Phase 2: Sysmon for Linux Deployment

Host telemetry was extended with **Sysmon for Linux**, installed via Microsoft's package repository:

\`\`\`bash
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
\`\`\`

![SysmonForLinux APT Installation](12-sysmonforlinux-apt-installation.png)

The initial install hit a missing-keyring warning (`/usr/share/keyrings/microsoft-prod.gpg is missing`), which cleared after re-running `apt update` against the newly added repo:

![Microsoft GPG Keyring Setup](13-microsoft-gpg-keyring-setup.png)
![Sysmon Package Upgrade Check](14-sysmon-package-upgrade-check.png)

Sysmon was then configured with a custom `sysmonconfig.xml` covering process creation, network connections, and file creation events:

\`\`\`xml
<Sysmon schemaversion="4.81">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
\`\`\`

![Sysmon XML Config Creation](15-sysmon-xml-config-creation.png)

\`\`\`bash
sudo sysmon -i sysmonconfig.xml
\`\`\`

Configuration validated successfully and Sysmon registered as a systemd service.

![Sysmon Service Initialization](16-sysmon-service-initialization.png)
![Sysmon eBPF Manifest Verification](17-sysmon-ebpf-manifest-verification.png)

---

## Phase 3: Network IDS — Snort to Suricata Pivot

Snort was the original choice for network IDS, but the package wasn't locatable via `apt` even after enabling the `universe` repository:

\`\`\`bash
sudo apt install -y snort
# Error: Unable to locate package snort
\`\`\`

![Snort Package Locate Error](18-snort-package-locate-error.png.png)
![Ubuntu Universe Repo Enable](19-ubuntu-universe-repo-enable.png)
![Sudo Update](20-sudoupdate.png)
![Snort Install Reattempt](21-snort-install-reattempt.png)

The lab pivoted to **Suricata** instead. The initial `systemctl start suricata` attempt failed (`exit-code`):

![Suricata Failed Service](22-suricata-failed-service.png)

A ruleset update was run, loading **68,018 rules** (52,084 enabled):

![Suricata Ruleset Update](23-suricata-ruleset-update.png)
![Suricata Ruleset Compilation](24-suricata-ruleset-compilation.png)

The restart still failed, which was root-caused by checking the actual network interface with `ip -br addr` — the running interface was `enp0s3`, not what `suricata.yaml` was configured to bind to:

![Suricata Restart Error](25-suricata-restart-error.png)
![Network Interface Enumeration](26-network-interface-enumeration.png)

After validating the config and updating the `af-packet` interface binding in `suricata.yaml`:

\`\`\`yaml
af-packet:
  - interface: enp0s3
    cluster-id: 99
\`\`\`

![Suricata YAML Test Pass](27-suricata-yaml-test-pas.png)
![Suricata YAML Interface Binding](28-suricata-yaml-interface-binding.png)

The service started and was enabled for persistence:

\`\`\`bash
sudo systemctl start suricata
sudo systemctl enable suricata
sudo systemctl status suricata
# Active: active (running)
\`\`\`

![Suricata Service Start Command](29-suricata-service-start-command.png)
![Suricata Enable Boot Persistence](30-suricata-enable-boot-persistence.png)
![Suricata Service Active Running](31-suricata-service-active-running.png)
![Fleet Agent Healthy Overview](32-fleet-agent-healthy-overview.png)

The Suricata integration was then added to the Fleet agent policy to collect `eve.json` logs, giving the policy both System and Suricata integrations:

![Kibana Suricata Integration Add](33-kibana-suricata-integration-add.png)
![Suricata Integration Tags Config](34-suricata-integration-tags-config.png)
![Policy Dual Integrations Active](35-policy-dual-integrations-active.png)

---

## Phase 4: Telemetry Verification

Nmap scans against loopback (`127.0.0.1`) and the VM's actual interface (`10.0.2.15`) were used to generate test telemetry:

![Nmap Loopback Scan Execution](36-nmap-loopback-scan-execution.png)
![Nmap Adapter Scan Execution](37-nmap-adapter-scan-executio.png)

Verifying this in Kibana Discover surfaced a real debugging step worth documenting: an initial query for `process.name : "nmap"` against the default Security Solution data view returned **no results**.

![Kibana Query No Results Check](38-kibana-query-no-results-check.png)

Switching to the `logs-*` data view surfaced ingestion:

![Kibana Logs Data View Ingestion](39-kibana-logs-dataview-ingestion.png)
![Kibana Suricata Eve Verification](40-kibana-suricata-eve-verification.png)

A second strict field-name query still missed:

![Kibana Query Strict Field Miss](41-kibana-query-strict-field-miss.png)

Broadening the query to `*nmap*` finally matched the Sysmon-side process execution records — the original query had been scoped to the wrong data view and an overly strict field match:

![Kibana Sysmon Nmap Execution Matched](42-kibana-sysmon-nmap-execution-matched.png)

---

## Phase 5: Threat Simulation — SSH Brute Force

Prepping for the brute-force phase revealed `ssh.service` wasn't present by default:

![SSH Service Not Found Error](43-ssh-service-not-found-error.png)

`openssh-server` was installed and the service enabled/started:

![OpenSSH Server Installation](44-openssh-server-installation.png)
![SSH Service Active Running](45-ssh-service-active-running.png)

An SSH brute-force attack was then simulated locally with Hydra:

\`\`\`bash
hydra -l ubuntulabenv -P /usr/share/dict/words ssh://127.0.0.1 -t 4 -V
\`\`\`

![Hydra Bruteforce Command Launch](46-hydra-bruteforce-command-launch.png)

The run self-throttled before completing (`all children were disabled due too many connection errors`) without recovering valid credentials — expected behavior against a hardened local SSH config, and still generated the authentication-failure telemetry needed for detection testing.

![Hydra Bruteforce Execution Limit](47-hydra-bruteforce-execution-limit.png)

Kibana confirmed the attack in the `system.auth` data stream:

![Kibana System Auth Log Stream](48-kibana-system-auth-log-stream.png)

A `*Failed password*` search returned **637 matching documents**:

![Kibana Failed Password Events](49-kibana-failed-password-events.png)

---

## Phase 6: Detection Rule Configuration & Alert Trigger Verification

This final phase walks through the full detection rule build — start to finish — ending in a confirmed, triggered alert.

A custom KQL threshold rule was authored in Kibana Security's detection rules engine:

![Elastic Security Rules Engine](50-elastic-security-rules-engine.png)
![SIEM Rule Type Selection](51-siem-rule-type-selection.png)

**Query definition** — `event.dataset : "system.auth" and event.action : "ssh_login"`:

![KQL Query Definition](52-kql-query-definition.png)
![Threshold Rule Type Selected](53-threshold-rule-type-selected.png)

**Threshold tuning** — the platform default of 200 was far too high to ever fire against this lab's traffic volume, so it was deliberately adjusted down to **5** to match realistic detection sensitivity for a single-host environment:

![Threshold Default Limit Check](54-threshold-default-limit-check.png)
![Threshold Value Adjusted](55-threshold-value-adjusted.png)

**Group By** was set to `source.ip`, so alerts trigger per attacking source rather than in aggregate:

![Rule GroupBy SourceIP Config](56-rule-groupby-sourceip-config.png)

**Rule metadata** — named "SSH Brute Force Detection - Local Host," severity High, risk score 73:

![Rule Metadata High Severity](57-rule-metadata-high-severity.png)
![Rule Description Threat Mapping](58-rule-description-threat-mapping.png)

**Schedule** — set to run every 5 minutes:

![Rule Schedule Evaluation Window](59-rule-schedule-evaluation-window.png)

**Final rule summary**, reviewed and enabled:

![Rule Definition Summary Enabled](60-rule-definition-summary-enabled.png)

**Description:** *"Detects multiple failed SSH authentication attempts within a 5-minute window from a single source IP, indicating potential brute-force or credential stuffing activity against the local system."*

### Result: Triggered Alert

Upon execution, the rule evaluated incoming `system.auth` events, correlated the high-frequency failed-password activity from `127.0.0.1`, and generated a confirmed high-severity alert — closing the loop from attack simulation to detection.

![Triggered SIEM Alert Verified](61-triggered-siem-alert-verified.png)

**Alert detail:** *"event with source 127.0.0.1 created high alert SSH Brute Force Detection..."* — Severity: High, Risk Score: 73.

---

## Key Takeaways & Skills Demonstrated

* Deployed and enrolled Elastic Agent via Fleet, configuring a policy with dual host (System, Sysmon) and network (Suricata) integrations for full-spectrum visibility.
* Diagnosed and resolved real infrastructure issues independently: apt lock conflicts, DKMS/VirtualBox mount failures, a missing GPG keyring, and a NIDS service failure traced to an incorrect network interface binding.
* Adapted the toolchain under real constraints, pivoting from Snort to Suricata when the intended package wasn't available.
* Debugged a Kibana data-view and field-scope mismatch during telemetry verification rather than assuming ingestion had failed.
* Executed controlled threat simulations (Nmap, Hydra) to generate and validate authentic detection telemetry.
* Authored and tuned a custom KQL threshold detection rule, adjusting default thresholds to match realistic lab-scale traffic rather than relying on out-of-the-box settings.
* Verified full-loop detection: attack execution → ECS-parsed ingestion → rule evaluation → triggered, confirmed alert.
