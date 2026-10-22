DEPLOYING AN INTERNET-FACING HONEYPOT - FOR THREAT INTELLIGENCE

>Under Construction
(image)

112k Events in 72h + 2100 Unique Ip's

**Author:** Tiago Bastos  
**Date:** October 2026  

> **Privacy / GDPR note**  
> All public IP addresses belonging to me and to the honeypot virtual machine will be anonymized in any public version of this report.  
> Attacker IPs are partially masked (first two octets retained for easyer perception of evidence).  
> Credential lists and command histories are retained because they represent common attacker behaviour observed on an intentionally exposed research system.  
> No malware binaries are published — only cryptographic hashes.

---

## TABLE OF CONTENTS

1. Executive Summary  
2. Project Objectives  
3. Environment & Architecture  
4. Honeypot Deployment Walkthrough  
5. Microsoft Sentinel Deployment  
6. Log Analysis & Key Findings  
7. Analytics Rules  
8. Verified High-Severity Cases (Evidence from Logs)  
9. Who Are the Attackers? Why?  
10. Challenges Encountered and Solutions  
11. Cost Breakdown  
12. Conclusion & Recommendations  
13. Appendix – Evidence Index & Chain of Custody  

---

**1. EXECUTIVE SUMMARY**

This report documents the deployment, integration, and threat analysis of an internet-facing cloud honeypot designed to capture real-world cyberattack data for proactive threat intelligence. Using Microsoft Azure, a Linux virtual machine was provisioned to host the T-Pot, incorporating multiple honeypot services including Cowrie, Dionaea, Conpot and Suricata. Ingestion pipelines were established to forward security events to Microsoft Sentinel for centralized SIEM log management, custom alert generation, and KQL-based analytics.
An Internet-facing T-Pot honeypot was deployed on Microsoft Azure (Spain Central) with the following active services:

- **Cowrie** – SSH/Telnet medium-interaction  
- **Conpot** – ICS/OT protocols (IEC 104, SNMP, Kamstrup, etc.)  
- **Dionaea** – low-interaction malware capture (FTP, MySQL, SMB, …)  
- **Tanner** – web application honeypot  
- **Suricata** – network IDS  
- Local ELK stack for visualisation and comparison 

Operating over an exposure window of approximately 72 hours, the honeypot captured 112000+ events recorded originating from 2100+ distinct IP addresses. Detailed log analysis revealed high-volume attack vectors across targeted ports, primary geographic sources, and observed threat actor Tactics, Techniques, and Procedures (TTPs).

Logs were forwarded in near real-time to a Microsoft Sentinel workspace via Azure Monitor Agent and a custom Data Collection Rule (`dcr-honeypot`).  

In a ~72-hour observation window the honeypot recorded:

| Source     | Total events (approx.) | Key metric                          | Unique source IPs |
|------------|------------------------|-------------------------------------|-------------------|
| Cowrie     | ≈ 84 500               | 797 successful logins               | 150 (successful logins) |
| Dionaea    | ≈ 11 250               | 8 632 credential attempts           | 49                |
| Tanner     | ≈ 11 830               | 11 817 HTTP requests                | 204               |
| Conpot     | **1 827** (full raw, all days) | SNMP / Kamstrup / IEC104 / guardian_ast dominant | **203** (202 excl. author) |
| Suricata   | ≈ 725 000 total / **33 232** alerts (full raw) | DoublePulsar, SSH scans, SNMP, web scans | **1 497** (1 493 excl. internal Azure + author) |

> **Note on Cowrie**  
> The ELK / Elasticsearch dashboard shows ≈ 84 500 Cowrie documents. These are *all* event types (session.connect, client.version, login.failed, login.success, command.input, session.closed, …).  
> Only **797** of them are `cowrie.login.success`, coming from **150 unique source IPs**.  
> The number of unique IPs that merely *connected* (without necessarily succeeding) is higher; the current evidence package contains only the top-20 by connection volume.

> **Note on Conpot / Suricata**  
> Earlier drafts used only the current (non-rotated) log files. The values above come from a full re-parse of every rotated `.json` / `.json.*.gz` covering 18–21 October 2026.

Custom analytic rules mapped to MITRE ATT&CK (including ATT&CK for ICS) generated alerts. Three **High** severity rules produced actionable findings that were cross-verified against the raw logs:

1. **Persistence Attempts** – ex: mass installation of SSH authorized_keys  
2. **Malware captured** – 4 distinct files captured (MD5 in Appendix 13), 1 identified as a trojan 
3. **Payloads in POST bodies** – 156 alerts from a single scanner; the rule was rewritten after the evaluation (see 8.3)

Operational mitigations were required after the Conpot container was driven to 100 % CPU four times by four different scanners (see 6.2.1).

The 22 analytic rules were deployed as a ~72-hour evaluation. Some alerts are therefore noise, repeats or the result of misconfigured rules; this is documented in 7.1 and listed as an improvement.

Total Azure cost for the period: **€15.03**.


This project demonstrates how automated entities continuously probe exposed services while proving the utility of honeypots and SIEM integration in threat research. Operational hurdles, including port binding conflicts and active scanning attacks that compromised Docker service stability, required mitigation. The total infrastructure cost incurred was approximately 15€, funded via Azure for Students credits.


2. PROJECT OBJECTIVES

The primary goals of this project were:
• Deploy Cloud Infrastructure: Provision an internet-facing Linux host on Microsoft Azure running the T-Pot Community Edition framework.
• Simulate Exposed Targets: Emulate vulnerable services across multiple protocols (SSH, HTTP, SMB) with a primary focus on ICS/SCADA environments (e.g., using Conpot alongside Cowrie and Suricata) to capture unsolicited internet traffic.
• Establish SIEM Ingestion: Build custom ingestion pipelines and connectors to stream logs from local containerized services to Microsoft Sentinel.
• Threat Detection & KQL Rules: Construct custom Kusto Query Language (KQL) analytics rules focusing on MITRE ATT&CK TTPs, brute-force patterns, and targeted probing of industrial control protocols.
• Document Technical Challenges: Identify and resolve deployment friction points, such as Docker container orchestration, port conflicts, and disabling active modules (e.g., SpiderFoot) to avoid unwanted outbound scanning reports.
• Deliver Cost-Aware Intelligence: Produce an actionable threat intelligence report mapping real-world threat actor behaviors while maintaining cost controls.
• Ensure Regulatory Compliance: Practice privacy-by-design by anonymizing/obfuscating IPv4/IPv6 data to align with GDPR guidelines prior to publishing findings.


## 3 Environment and architecture

### 3.1 Azure

| Item | Value in evidence |
|---|---|
| Virtual machine resource group | `RG-HONEYPOT-LAB` |
| Region | Spain Central |
| OS | Linux, Debian 13 |
| Size | Standard D4s v4 (4 vCPU, 16 GiB memory), 128 GB disk |
| Virtual network / subnet | `vnet-hp` / `snet-hp` |
| NIC | `VM-TPOTVMNIC` |
| NSG | `nsg-hp`, associated to that NIC |
| Sentinel resource group | `sentinel-trial` |
| Workspace | `tpot-sentinel` |
| Data collection endpoint | `dce-hp-ne` |
| Data collection rule | `dcr-honeypot`, kind Linux, provisioning Succeeded |
| Public IP | *anonymised as x.x.x.x in public version*  |

### 3.2 Network Security Group (NSG)

Management ports (64294, 64295, 64297) were restricted to the author’s home IP only.  

Honeypot ports (expanded set used during the experiment):

**TCP:** 20, 21, 22, 23, 42, 80, 81, 135, 443, 445, 502, 1025, 1433, 1723, 1883, 2404, 3306, 3389, 5555, 5900, 6379, 9200, 9300, 10001, 11112, 11211, 27017, 44818, 47808, 50100  

**UDP:** 69, 123, 161, 623, 1900, 5000, 5060, 5353  

A temporary deny rule (`block-attack1`) was added for four aggressive source IPs after a Conpot CPU exhaustion incident.

<img width="1000" height="512" alt="ksnip_20261019-190705(2)" src="https://github.com/user-attachments/assets/0dae8720-376f-490d-aa42-ee5f35648053" />


### 3.3 Data-flow architecture

```
     Internet 
        │
        ▼
┌───────────────────────┐
│  Azure NSG + iptables │
└───────────┬───────────┘
            │
┌───────────▼───────────┐
│  T-Pot (Docker)       │
│  Cowrie / Conpot /    │
│  Dionaea / Tanner /   │
│  Suricata + ELK       │
└───────────┬───────────┘
            │ JSON logs
┌───────────▼───────────┐
│  Azure Monitor Agent  │
│  + DCR dcr-honeypot   │
└───────────┬───────────┘
            │
┌───────────▼───────────┐
│  Log Analytics        │
│  workspace            │
│  tpot-sentinel        │
└───────────┬───────────┘
            │
┌───────────▼───────────┐
│  Microsoft Sentinel   │
│  Analytic Rules       │
│  → SecurityAlert      │
└───────────────────────┘
```

---

## 4. Honeypot Deployment Walkthrough

*(Commands used for the initial T-Pot installation and Azure VM provisioning will not be inserted, the reference instalattion T-pot guide should be followed)*

Honeypot Stack: Base installation with default T-Pot with some costum made mods, it's wasn't used all the capabilities, used removed totally the spiderfoot to avoid deploys automatic scans.

The honeypot stack was modified to working service ports for the following services:
• Cowrie – Emulates SSH and Telnet to capture login attempts and shell interactions.
• Conpot – Simulates industrial control systems (ICS/SCADA) to attract infrastructure-targeted
attacks.
• Dionaea – Collects malware by mimicking vulnerable services like SMB, HTTP, and FTP.
• Suricata – A network intrusion detection and prevention system that analyzes and logs
malicious traffic.
• Tanner – Web application honeypot that emulates vulnerable web apps and classifies HTTP requests (index, XSS, RFI, CRLF, WordPress probes).
• Nginx -  Management and Kibana dashboards 

• A custom Network Security Group (NSG) was configured to expose only the
necessary ports.

---


## 5. Microsoft Sentinel Deployment

I will not make a walktrough installation for the deploynment as the Sentinel it's in construction, and should be followed the official information from Microsoft.

i will provide some prove of validations to make the complete set of DCR and validations for the AMA (Azure Monitor Agent) required to forward logs from linux machines to a resource group in Azure.

Image x: AMA Install in RG.
<img width="1261" height="397" alt="ksnip_20261018-163257(4)" src="https://github.com/user-attachments/assets/8dd943fd-67f8-46e8-b0b2-9db7ff5a87d1" />


### 5.1 Data Collection Rule

The DCR declares five custom streams:

- `Custom-CowrieJson` → `Custom-Cowrie_CL`  
- `Custom-ConpotJson` → `Custom-Conpot_CL`  
- `Custom-DionaeaJson` → `Custom-Dionaea_CL`  
- `Custom-SuricataJson` → `Custom-SuricataAlerts_CL` (alerts only)  
- `Custom-TannerJson` → `Custom-Tanner_CL`  

All streams set `TimeGenerated` from the original timestamp and drop noisy internal fields.

### 5.2 Analytic Rules Overview

Twenty-two scheduled rules were deployed (exported as an ARM template) and left running for the ~72 h observation window (18 to 21 October) as an evaluation. Severity distribution:

- **High**: 3 rules
- **Medium**: 14 rules
- **Low**: 5 rules

Twenty-two rules produced alerts (5,428 in total). Full list with MITRE mapping is in Section 7.

---

## 6. Log Analysis & Key Findings

### 6.1 Cowrie

| Metric                              | Value                          |
|-------------------------------------|--------------------------------|
| Total events (ELK / Elasticsearch)  | ≈ 84 500                       |
| Successful logins (`login.success`) | 797                            |
| Unique source IPs (successful only) | **150**                        |
| Most successful single IP           | 160.119.x.x (454 logins)       |
| Top username (all attempts)         | root (4 654 attempts)          |
| Top password (all attempts)         | 123456                         |
| Most common successful pair         | enable:linuxshell (454)        |
| File downloads                      | 117 (4 unique SHA-256, none with a source URL; 77 are the `mdrfckr` key file) |
| File uploads                        | 10 (one is an empty file) |

> The 150 unique IPs refer **only** to sources that achieved at least one successful login.  
> The number of distinct IPs that merely opened a TCP connection (session.connect) is higher; the evidence package currently contains only the top-20 by connection volume (already > 12 000 connections from those 20 IPs alone).

**Dominant post-compromise behaviour**

- Installation of a hard-coded SSH public key (`mdrfckr`) into `~/.ssh/authorized_keys`  
- `crontab -l` and related persistence checks  
- Architecture fingerprinting (`uname`, `busybox`, CPU model strings)  
- Occasional `wget`/`curl` dropper activity  

Image x - botnet style ttp
<img width="1168" height="182" alt="image" src="https://github.com/user-attachments/assets/030248fd-f3f4-4535-8b58-efd1bc80ca2b" />

Curled/wget IOC's
<img width="1299" height="539" alt="ksnip_20261021-195451" src="https://github.com/user-attachments/assets/79563054-5711-4f81-9bd5-bcc30bbb1e2a" />
<img width="972" height="653" alt="ksnip_20261021-195454" src="https://github.com/user-attachments/assets/5b391258-b5eb-459c-8e58-d6a9f552df1e" />



### 6.2 Conpot (OT/ICS)

> **Data coverage (corrected).** Full re-parse of every rotated Conpot log (`conpot_*.json*`) covering **18–21 October 2026** yields **1 827 events** from **203 unique source IPs** (202 excluding the author management IP).  
> Daily volume: 18 Oct 590 · 19 Oct 771 · 20 Oct 275 · 21 Oct 191.

| Protocol (`data_type`) | Typical port | Events (full) | MITRE ATT&CK for ICS | Sentinel rules that cover it |
|---|---|---|---|---|
| SNMP (`snmp`) | 161/udp | **629** | T0888 (T1602.001 Enterprise) | SNMP enumeration, SNMP flood, SNMP SET attempts |
| Kamstrup protocol (`kamstrup_protocol`) | 1025/tcp | **397** | T0883, T0846 | OT/ICS protocol interaction, Multi-port OT scanner |
| Guardian AST (`guardian_ast`) | 10001/tcp | **323** | T0883, T0846 | OT/ICS protocol interaction |
| IEC 60870-5-104 (`IEC104`) | 2404/tcp | **241** | T0883, T0846 | OT/ICS protocol interaction, Multi-port OT scanner |
| Kamstrup management (`kamstrup_management_protocol`) | 50100/tcp | **211** | T0883, T0846 | OT/ICS protocol interaction |
| IPMI (`ipmi`) | 623/udp | **22** | T0888 | OT/ICS protocol interaction |
| EtherNet/IP (`enip`) | 44818/tcp | **4** | T0883, T0846 | OT/ICS protocol interaction |
| **Total (full raw)** | | **1 827** | | |

| Top sources | Events | Notes |
|---|---|---|
| `40.78.x.x` | 402 | Also top Tanner / Suricata source; one of the Conpot CPU attackers; later blocked |
| `x.x.x.x` | 282 | Author management IP (anonymised) |
| `178.166.x.x` | 245 | Heavy Kamstrup activity |
| `35.195.x.x` | 61 | Cloud scanner |
| `165.154.x.x` | 26 | |
| `3.129.x.x` / `18.218.x.x` | 24 each | AWS-range scanners |

Cross-check with Sentinel (alerts over the full ~72 h): OT/ICS protocol interaction 857 alerts / 156 IPs, Same IP on SSH and OT honeypots 211 / 12, Multi-port OT scanner 84 / 5, Persistent OT visitor 7 / 5, SNMP flood 6 / 1, SNMP enumeration 2 / 2, SNMP SET attempts 2 / 1, Same IP on web and SNMP 20 / 1.

The dominant protocol is **SNMP** (read requests), followed by the two Kamstrup variants and Guardian AST. The full extract confirms that the earlier 12-hour sample severely under-represented SNMP and Kamstrup volume.

### 6.2.1 Conpot 100 % CPU incident

**Impact.** Four sources, each in turn, drove the Conpot container to 100 % CPU. While the container was pegged, Conpot stopped answering, so the sensor was blind to OT traffic until it was restarted.

**Trigger.** A flood of malformed HTTP GET requests (port 80, Conpot HTTP template) combined with SNMP traffic on port 161 (UDP), with connections dropped mid-request. The container entered a loop and kept a core at 100 % without needing further traffic.

**Sources (all later added to the NSG `block-attack1` deny rule):**

| Source  | Evidence across sensors (full extracts) | Role |
|---|---|---|
| `40.78.x.x` | Tanner: **10 006** requests in 30 min (19 Oct 08:08–08:38 UTC, peak 2 068 req/min, 5 819 distinct paths); Conpot: **402** events; Suricata: **4 008** alerts | Primary CPU attacker; also top web / OT / IDS source |
| `189.150.x.x` | Cowrie: **1 144** session.connect | High-volume SSH scanner |
| `66.132.x.x` | Censys scanner range; present in Conpot and Suricata | Internet-wide scanner |
| `77.110.x.x` | Listed in `block-attack1` | Early CPU trigger |

`40.78.x.x` is in Microsoft Azure address space (Azure-hosted scanner). The same IP dominates three sensors at once, which is why a single source could both exhaust Conpot and generate the bulk of Tanner and Suricata noise.

image x - attack to honeypot that caused 100 cpu usage to conpot container incident.
<img width="653" height="442" alt="ksnip_20261019-101129(3)" src="https://github.com/user-attachments/assets/07a5b5c4-7962-4635-a532-e2bf687e26da" />
<img width="1200" height="912" alt="image" src="https://github.com/user-attachments/assets/e072de24-7eb6-4aca-98dc-484577e2efe2" />
The attacker flooded the machine with malformed GET requests and dropped connections, causing a loop bug in the container that led to 100 % CPU usage.
<img width="1038" height="692" alt="ksnip_20261019-101129(4)" src="https://github.com/user-attachments/assets/db48d835-265e-44b3-ac99-e26caf8ce90c" />
<img width="987" height="705" alt="ksnip_20261019-190705" src="https://github.com/user-attachments/assets/acdf667a-93f0-4f8f-83d2-b47f55f53786" />

**Timeline** (to be completed from the screenshots and `az monitor activity-log`):

| Step | Time (UTC) | Evidence |
|---|---|---|
| First CPU spike | TBD | screenshot |
| First source blocked in `block-attack1` | TBD | activity log |
| Second, third, fourth spikes and blocks | TBD | screenshots |
| Final mitigation in place (iptables + watchdog) | TBD | cron / iptables |

**Why the block list alone failed.** Each new scanner re-triggered the bug. Blocking by source is reactive and always one incident behind.

**Layered fix.**
1. NSG deny rule for the offending sources (reactive).
2. iptables rate limit, dropping after 100 requests in 30 s.
3. A watchdog (cron plus script) that restarts the container when CPU exceeds 75 %.

**Future Improvements:** a Docker CPU limit on the Conpot container, a container health check, and an Azure Monitor alert on CPU so the first incident is detected automatically.

image - NGS updated block list.
<img width="1055" height="342" alt="image" src="https://github.com/user-attachments/assets/0eea8996-96fe-49fc-9d93-2bb17841eec9" />


image x - Conpot Validation Logs response at MS defender
<img width="1140" height="816" alt="ksnip_20261018-181334" src="https://github.com/user-attachments/assets/d881e691-fd68-423d-97e2-482c6edcb59a" />


### 6.3 Dionaea

| Metric                    | Value      |
|---------------------------|------------|
| Total events (ES)         | ≈ 11 250   |
| Credential attempts       | 8 632      |
| Unique source IPs         | **49**     |

- Predominantly MySQL on port 3306 with empty passwords for `root`/`admin`/`sa`.  
- Credential attempts by service: MySQL 8,594 (port 3306), MSSQL 32 (1433), FTP 6 (21). Usernames `root`, `sa` and `admin` account for about 2,900 attempts each; 8,616 of the 8,632 passwords are empty.
- Four distinct malware files were captured (MD5 in Appendix 13); one was identified as a trojan on VirusTotal. In the evidence package `binaries.tgz` is empty and only `binaries.tgz.1` and `.2` hold data.
- Only cryptographic hashes are retained for the report.

Virus Total Report:
<img width="1172" height="630" alt="ksnip_20261019-190705(3)" src="https://github.com/user-attachments/assets/1febf8e6-473d-441a-9474-82f2d8800154" />
<img width="1530" height="651" alt="cowriedownload1" src="https://github.com/user-attachments/assets/24b4b143-2bbf-4872-b2e0-27879066e1c3" />


### 6.4 Tanner (HTTP)

| Metric                | Value                          |
|-----------------------|--------------------------------|
| Total requests        | 11 817                         |
| Unique source IPs     | **204**                        |
| Top path              | `/` (996)                      |
| Notable paths         | `/.env` (35), `/login`, Qualys probes |
| Top source IP         | 40.78.x.x (10 006 requests = 85 % of all, in 30 min on 19 Oct, 08:08 to 08:38 UTC, peak 2 068 requests/min, 5 819 distinct paths) – blocked, one of the sources of the Conpot 100 % CPU incidents |
| Methods               | GET 11 372, POST 391, HEAD 25, OPTIONS 13, TRACE 6, PROPFIND 5 |
| POST requests with a body | 199 (160 from 40.78.x.x) |
| Detections            | `index` 11 190, `unknown` 358, `xss` 204, `wp-content` 61, `crlf` 3, `rfi` 1 |
| Period covered        | 18 Oct 12:54 to 21 Oct 12:53 UTC (complete) |

<img width="635" height="650" alt="ksnip_20261019-111116" src="https://github.com/user-attachments/assets/f2761599-b11f-4668-b3c8-1c65ebb6d7db" />
<img width="887" height="632" alt="ksnip_20261019-121448" src="https://github.com/user-attachments/assets/1504aaff-0d3b-4cec-81ce-322c568af758" />


### 6.5 Suricata

| Metric                                      | Value                          |
|---------------------------------------------|--------------------------------|
| Total events (ES)                           | ≈ 725 000                      |
| Alerts (full raw, all rotated eve.json*)    | **33 232**                     |
| Unique source IPs (all alerts)              | **1 497**                      |
| Unique source IPs (excl. internal Azure + author) | **1 493**                |

> Full re-parse of `eve.json` + `eve.json.1.gz` … `eve.json.5.gz` (18–21 Oct).  
> Internal Azure addresses (`10.10.0.4`, `169.254.169.254`, `168.63.129.16`) still dominate the raw count and are filtered by the DCR transform before Sentinel.

**Top signatures (full extract)**

| Count | Signature |
|------:|-----------|
| 8 696 | ET INFO HTTP Request on Unusual Port Possibly Hostile |
| 4 558 | ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| 1 834 | SURICATA STREAM RST recv but no session |
| 1 493 | ET INFO SSH session in progress on Expected Port |
| 1 205 | ET INFO SSH-2.0-Go version string Observed in Network Traffic |
| 1 090 | GPL TELNET Bad Login |
|   711 | ET DROP Dshield Block Listed Source group 1 |
|   702 | GPL SNMP request udp |
|   645 | GPL SNMP public access udp |
|   592 | ET SCAN Potential SSH Scan |
|   477 | ET SCAN NMAP -sS window 1024 |
|   465 | ET INFO BusyBox Banner Observed |
|   458 | ET HUNTING Possible Apache log4j RCE Attempt (CVE-2021-44228) |
|   435 | ET SCAN Suspicious inbound to mySQL port 3306 |

**Top external sources (masked, internal Azure removed)**

| Count | Source (masked) | Notes |
|------:|-----------------|-------|
| 4 008 | `40.78.x.x` | Same IP that flooded Tanner and Conpot; later blocked |
| 1 575 | `196.190.x.x` | |
| 1 507 | `176.211.x.x` | |
| 1 435 | `129.205.x.x` | |
|   529 | `93.123.x.x` | Frequent PPTP / DROP hits |
|   456 | `x.x.x.x` | Author management IP (anonymised) |
|   267 | `31.7.x.x` | |
|   246 | `77.239.x.x` | Also heavy on Cowrie |

Notable findings: **DoublePulsar** (SMB backdoor install pattern) is the second most frequent signature; log4j probing and BusyBox banners confirm opportunistic IoT/botnet activity alongside classic SSH and SNMP scans.  

Image x - Validation of evidence attack on Defender from source Suricata
<img width="1130" height="738" alt="ksnip_20261019-121454" src="https://github.com/user-attachments/assets/72c85e74-f304-4d3d-bf68-9d879278fd26" />


---

## 7. Analytics Rules

All rules except rule 17 (rewritten, see 8.3) exclude the author's management IP. Alerts are counted from the exported `SecurityAlert` table. "Distinct IPs" counts the IP entity of each alert.


| # | Rule | Sev | Tactic(s) | Technique(s) Enterprise | ICS | Alerts | Distinct IPs | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | HP - Cowrie successful login | Low | Initial Access | T1078 | n/a | 2,324 | 148 | Fired, noisy (2.9 alerts per real login) |
| 2 | Persistence Attempts | **High** | Persistence, Execution | T1098.004, T1053.003, T1136.001, T1037.004 | n/a | 572 | 42 | Fired, verified |
| 3 | Dropper activity | Med | Command and Control | T1105, T1059.004 | n/a | 20 | 4 | Fired |
| 4 | Credential reuse | Med | Credential Access | T1110.004 | n/a | 209 | none (entity mapping missing) | Fired, needs fix |
| 5 | Malware captured | **High** | Command and Control | T1105 | n/a | 18 | 4 (13 alerts have no IP entity) | Fired, verified |
| 6 | Credential guessing on services | Med | Credential Access | T1110.001, T1110.003 | n/a | 35 | 6 | Fired |
| 7 | OT/ICS protocol interaction | Med | Reconnaissance | T1595 | T0883, T0846 | 857 | 156 | Fired |
| 8 | Multi-port OT scanner | Med | Reconnaissance | T1595 | T0846, T0840 | 84 | 5 | Fired |
| 9 | Persistent OT visitor | Low | Reconnaissance | T1595 | T0883 | 7 | 5 | Fired |
| 10 | Same IP on SSH and OT honeypots | Med | Reconnaissance | T1595 | T0883 | 211 | 12 | Fired |
| 11 | SNMP enumeration | Low | Collection | T1602.001 | T0888 | 2 | 2 | Fired |
| 12 | SNMP flood | Med | Impact | T1498.001 | T0814 | 6 | 1 | Fired |
| 13 | SNMP SET attempts | Med | Collection, Impact | T1565.001 (to confirm) | T0836 | 2 | 1 | Fired |
| 14 | Web flood / fast scanner | Med | Impact | T1499.002 | n/a | 477 | 4 | Fired, noisy |
| 15 | Exploit-style paths | Med | Initial Access | T1190 | n/a | 150 | 17 | Fired |
| 16 | Classified web attacks | Med | Initial Access | T1190 | n/a | **0** | n/a | Under evaluation (no alert) |
| 17 | Payloads in POST bodies (v2) | **High** | Initial Access, Execution | T1190, T1059, T1105, T1552.001 | n/a | 156 | 1 | v1 fired; rewritten as v2, needs re-evaluation |
| 18 | Same IP on web and SNMP | Med | Reconnaissance | T1595.002 | T0846 | 20 | 1 | Fired |
| 19 | Same IP on SSH and Dionaea | Low | Reconnaissance | T1595 | n/a | 205 | 13 | Fired  |
| 20 | Multi-service scanner | Med | Reconnaissance | T1595.001, T1046 | n/a | **0** | n/a | Under evaluation  |
| 21 | SMB/RPC scanning | Low | Lateral Movement (as configured) | T1210, closer to T1595 for inbound scans | n/a | 19 | 17 | Fired  |
| 22 | Database probing | Med | Initial Access | T1190, T1110.001 | n/a | 54 | 20 | Fired |

<img width="1145" height="931" alt="all rules" src="https://github.com/user-attachments/assets/e539453b-ccba-4626-9181-3fec653f807c" />

<img width="1144" height="899" alt="persistence attemp" src="https://github.com/user-attachments/assets/3076fdb3-9b69-4f26-82ce-48420a3f3a42" />

image x - Analytics Rule Sample Creation
<img width="842" height="800" alt="ksnip_20261018-172145" src="https://github.com/user-attachments/assets/028cf903-d9eb-4e95-88d6-810764190028" />
<img width="883" height="815" alt="ksnip_20261018-172145(2)" src="https://github.com/user-attachments/assets/767fa298-10e0-4514-bb3d-572dbe334ed4" />
<img width="898" height="758" alt="ksnip_20261018-172145(3)" src="https://github.com/user-attachments/assets/fa9ce220-cca1-4276-ae7d-e5922957091a" />

### 7.1 Repeated alerts (known limitation, listed as an improvement)

Several rules run every 5 to 15 minutes with a lookback of 1 h or more and one alert per result. The same event is therefore alerted again in every run that still sees it.

| Rule | Alerts | Underlying raw events | Ratio |
|---|---|---|---|
| Payloads in POST bodies (v1) | 156 | 39 matching POSTs from one IP (Tanner): 4 runs x 39 | 4.0 |
| Persistence Attempts | 572 | 78 `authorized_keys` commands (Cowrie) | 7.3 |
| HP - Cowrie successful login | 2,324 | 797 `login.success` events | 2.9 |
| Web flood / fast scanner | 477 | one burst: 10,006 requests in 30 min | n/a |
| Malware captured | 18 | 4 distinct MD5 | 4.5 (the same hash re-alerted hourly) |

The deployed rules also differ from the exported ARM template: the alerts report an 8 h lookback for Payloads in POST bodies (template: 1 h) and 6 h for Malware captured (template: 1 h). All 5,428 alerts were created with one alert per event and none was promoted to an incident.

Two further defects: Credential reuse has no entity mapping, and in Malware captured the IP entity is mapped to an array, so 13 of 18 alerts carry no IP. Improvements: set lookback equal to frequency, use event grouping by entity instead of one alert per result, aggregate with `summarize` per entity, fix the two mappings, add the missing techniques, and calibrate the two silent rules on a longer window.

---

## 8. Verified High-Severity Cases (Evidence from Logs)

Only **High** severity rules are illustrated below.  
Each case is cross-referenced with the raw log extracts that were pulled from the honeypot.

### 8.1 Persistence Attempts (T1098.004 / T1053)

<img width="1054" height="706" alt="image" src="https://github.com/user-attachments/assets/4dc3f9b4-03ee-44c2-b661-b85fd864f577" />


**Verified evidence (raw Cowrie log)**

Multiple independent source IPs executed the identical persistence command within minutes of a successful login:

```
cd ~ && rm -rf .ssh && mkdir .ssh && \
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr" \
>> .ssh/authorized_keys && chmod -R go= ~/.ssh
```

Observed from (among others):

- 80.94.x.x  
- 128.14.x.x  
- 172.190.x.x  
- 37.103.x.x  
- 58.147.x.x  

Immediately afterwards many of the same sessions ran `crontab -l`.

This is classic botnet behaviour that installs a shared back-door key and checks for existing cron jobs.

image x -  sample querie 
<img width="1054" height="706" alt="image" src="https://github.com/user-attachments/assets/61004b0c-6762-4936-ae82-01b93cf96343" />


### 8.2 Malware captured (Dionaea)

- Four distinct files were captured by Dionaea (MD5 values in Appendix 13); one was identified as a trojan.  

Only the cryptographic hashes are retained; the binaries themselves are kept offline and are **not** analysed further in this report.

Image x : image querie and hashes evidence by protocol.
<img width="842" height="679" alt="image" src="https://github.com/user-attachments/assets/842c5fd8-e872-496d-85cd-1303b342151c" />
Virus total evidence:
<img width="1175" height="392" alt="image" src="https://github.com/user-attachments/assets/81aa0e86-8476-4671-b818-84a080923861" />
<img width="1166" height="470" alt="image" src="https://github.com/user-attachments/assets/bd14ce0f-bc5b-429e-b01f-5670d4a5974a" />
<img width="1168" height="449" alt="image" src="https://github.com/user-attachments/assets/81341439-086a-4e49-935d-f5e9532c6e0d" />
<img width="1172" height="484" alt="image" src="https://github.com/user-attachments/assets/a9b2d71e-8620-4bb0-9087-6bf4c3f69b16" />


### 8.3 Payloads in POST bodies (T1190 / T1059)

**Rule logic (v1):** keywords `base64`, `eval`, `system`, `wget`, `curl`, `exec`, `passthru` in Tanner POST bodies. It matched 52 of the 199 POST bodies and produced 156 alerts (one source IP).

**Rule logic (v2, rewritten after the evaluation):** POST/PUT requests with a non-empty body that match an extended keyword list or whose path carries `auto_prepend_file`/`allow_url_include`. Each match is labelled with a payload family and summarised per source IP and family. The query has no time filter (frequency and lookback are set in the rule wizard) and no longer excludes the management IP.

```kusto
Tanner_CL
| where method in~ ("POST", "PUT")
| extend body = tostring(post_data)
| where isnotempty(body) and body != "{}"
| where body matches regex @"(?i)androxgh0st|__proto__|auto_prepend_file|allow_url_include|php://input|tangosol|primefaces|pfdrt|shell_exec|base64_decode|eval\(|system\(|passthru|exec\(|wget|curl|tftp|/bin/(ba)?sh|bash -c|cmd=|child_process|jndi:|<\?php|\.\./\.\./|/etc/passwd"
    or path has_any ("auto_prepend_file", "allow_url_include")
| extend Family = case(
    body has "androxgh0st", "androxgh0st",
    body has "__proto__", "react-proto-pollution",
    body has "tangosol", "weblogic-coherence",
    body has_any ("pfdrt", "primefaces"), "primefaces-el",
    body has_any ("shell_exec", "base64_decode"), "php-dropper",
    path has_any ("auto_prepend_file", "allow_url_include"), "php-cgi-arg-injection",
    body has_any ("wget", "curl", "tftp"), "download-cradle",
    "other-command")
| summarize Requests = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Paths = make_set(path, 5), UserAgents = make_set(user_agent, 3), Sample = take_any(substring(body, 0, 300))
          by src_ip, Family
```

<img width="796" height="359" alt="image" src="https://github.com/user-attachments/assets/4b0005a0-dc3d-41ac-8601-a660d82cbc7f" />

**Evidence (Tanner raw logs, 18 to 21 Oct):** 391 POST requests, 199 of them with a body. 52 bodies match the rule keywords: 39 from `40.78.x.x`, 5 from `168.222.x.x`, 5 from `190.171.x.x`, 2 from `152.236.x.x`, 1 from `96.62.x.x`. The 156 Sentinel alerts come from 39 events of the first source: the rule ran 4 consecutive times (5-minute frequency, 8 h deployed lookback) and returned the same 39 events each time (4 x 39 = 156), see 7.1. A Python replica of the v2 regex on the raw Tanner logs matches 107 of the 199 bodies; this still has to be confirmed by running the v2 query in Sentinel.

| Payload family (count) | Source | What it is | MITRE |
|---|---|---|---|
| PrimeFaces EL-injection probes with `cmd=cat /etc/passwd`, `wget $QIP:$QPORT`, `mstsc /v:$QIP:$QPORT` (at least 24) | `40.78.x.x` | Mass-scanner template, the `$QIP:$QPORT` placeholders were never filled in | T1190, T1059 |
| WebLogic console probes with `com.tangosol.coherence…` handle (14) | `40.78.x.x` | Looks like the WebLogic console ShellSession pattern (CVE-2020-14882 family, to verify) | T1190 |
| PHP-CGI argument injection (`-d allow_url_include=1 -d auto_prepend_file=php://input`, soft-hyphen `%AD`) | `40.78.x.x`, `168.222.x.x`, `190.171.x.x` | Pattern of CVE-2024-4577 (to verify) | T1190, T1059 |
| `shell_exec(base64_decode(…))` dropper (10) | `168.222.x.x`, `190.171.x.x` | Decodes to a shell script that writes a private key to `key.ppk`, then `scp`s a script from a remote host and runs it with argument `cve_2024_4577` | T1105, T1059.004 |
| React Server Components `$1:__proto__:then` (8) | `40.78.x.x`, `152.236.x.x` | Prototype-pollution RCE attempt (CVE-2025-55182 pattern, to verify) | T1190 |
| `0x[]=androxgh0st` (25) | `78.153.x.x` | Known Laravel/PHP credential-stealing botnet signature. **Not matched by v1**, because it has no keyword | T1190, T1552.001 |

The login-form POSTs in the logs (`{"login": ""}` 14 times, `ADMIN/ADMIN`, `admin/pass`) are credential guessing (T1110.001), not payloads, and are better handled by a separate rule.

> The v2 rule still needs validation on a longer dataset.

---

## 9. Who Are the Attackers? Why?

Brainstorm based on the observed telemetry:

1. **Commodity SSH botnets**  
   - Massive use of the same credential lists (`root`/`123456`, `enable`/`linuxshell`).  
   - Immediate installation of a shared SSH key (`mdrfckr`).  
   - Fingerprinting of architecture and busybox presence.  
   - Goal: build a large pool of compromised hosts for later DDoS / crypto-mining / proxy abuse.

2. **Opportunistic web scanners**  
   - Heavy probing of `/`, `/login`, `/.env`, Qualys-style paths.  
   - One IP alone generated >10 000 requests.  
   - Classic credential stuffing and vulnerability scanning.

3. **OT/ICS reconnaissance**  
   - Probes against IEC 104, SNMP, Kamstrup and guardian_ast.  
   - Low volume but high interest for industrial threat intelligence.

4. **Malware distribution**  
   - Four distinct malware files captured by Dionaea, one identified as a trojan.

5. **SMB / DoublePulsar-style probing**  
   - Suricata recorded **4 558** alerts for “ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication” — the second most frequent signature after unusual-port HTTP.  
   - Indicates widespread automated scanning for EternalBlue / DoublePulsar remnants on exposed SMB (445), consistent with commodity botnet and worm activity rather than a targeted campaign.

6. **Possible research / academic / OSINT scanners**  
   - Some low-and-slow, multi-protocol sources that did not attempt brute-force.  
   - Internet-wide scanners (e.g. Censys-range `66.132.x.x`, Shodan-style probes) that map exposed IoT and ICS devices; the data can be used for defence or for abuse.

The dominant motivation remains **automated compromise at scale** rather than targeted attacks against a specific organisation.

---

## 10. Challenges Encountered and Solutions

| Challenge                                      | Solution applied                                      |
|------------------------------------------------|-------------------------------------------------------|
| Conpot container driven to 100 % CPU           | NSG deny rule + iptables rate-limit (100 req/30 s) + script to evaluate container heath + cron job that restarts the container if CPU > 75 % |
| Extremely noisy “successful login” alerts      | Rule kept for visibility; grouping and suppression to be improved |
| Some analytic rules produced zero alerts       | Explicitly marked “Under evaluation” (Classified web attacks, Multi-service scanner) – expected on a short ~72 h window |
| JSON parse errors on a subset of Tanner lines  | Parsing line by line: all 11,817 Tanner lines parse (the jq errors probably came from reading rotated `.gz` files without `zcat`) |
| Repeated alerts (same event alerted in every overlapping run) | Documented in 7.1; fix by setting lookback equal to frequency, grouping by entity and summarising per entity |
| Deployed rules differ from the exported ARM template | Re-export the rules from the portal before documenting them |
| Conpot / Suricata initially under-counted | First extracts used only the current log file; full re-parse of all rotated `.json*` raised Conpot to 1 827 events and Suricata alerts to 33 232 |
| Dionaea `binaries.tgz` is empty | Samples are in `binaries.tgz.1` and `.2`; MD5 values taken from the Sentinel alerts |
| Suricata eve.json changing while being archived| Accepted; SHA-256 still recorded for chain of custody |
| Desire to keep malware evidence without risk   | Only hashes retained; binaries stay offline           |

---

## 11. Cost Breakdown

Azure Cost Analysis (October 2026, resource group `rg-honeypot-lab`):

| Service            | Cost    |
|--------------------|---------|
| Virtual Machines   | €12.53  |
| Storage            | €1.91   |
| Virtual Network    | €0.59   |
| Bandwidth          | €0.00   |
| Sentinel / LAW     | €0.00 (trial / free tier) |
| **Total**          | **€15.03** |

Location: Spain Central.  
No budget alerts were configured, but took limit rate of 8gb day no Sentinel workload.

---

## 12. Conclusion & Recommendations

The ~72-hour experiment successfully demonstrated:

- End-to-end telemetry pipeline from Internet-facing honeypots into Microsoft Sentinel.  
- Detection of real-world persistence, credential stuffing, OT reconnaissance and malware delivery.  
- Practical operational hardening under live attack.

**Recommendations for a follow-up engagement**

1. Extend the observation window to 7–14 days to give low-volume rules a chance to fire.  
2. Improve alert grouping / suppression for the “successful login” rule and for every rule with a lookback longer than its frequency (see 7.1).
   - Fix the two entity mappings (Credential reuse, Malware captured), add MITRE techniques to the rules that have none, and calibrate the two silent rules.
   - Put limits on the Conpot container (CPU limit, health check, Azure Monitor CPU alert).  
3. Add more ICS protocols and richer Conpot templates.  
4. Automate the evidence packaging (SHA-256 manifest + selective log extracts).  
5. Overlay the observed techniques on the MITRE ATT&CK Navigator (including the ICS matrix).  

The 22 rules were an evaluation run of ~72 hours: some alerts are noise, repeats or the product of misconfigured rules, and that is part of the findings rather than a defect of the data.

The project already provides a solid, recruiter-friendly artefact that shows hands-on experience with honeypots, Azure Sentinel, detection engineering and privacy-aware research.

---

## 13. Appendix – Evidence Index & Chain of Custody

### 13.1 Malware hashes (from the Malware captured alerts)

| MD5 | Alerts | First seen (UTC) | Last seen (UTC) |
|---|---|---|---|
| `70ccd9220cebb56eaa38b9f1bd1a1cd8` | 6 | 2026-10-19 22:08 | 2026-10-20 03:09 |
| `33d373e264dc7fdb0bcdbd8e075a6319` | 3 | 2026-10-19 21:08 | 2026-10-19 23:09 |
| `bedea9a1132892eb9041c601f2a49d03` | 2 | 2026-10-20 10:25 | 2026-10-20 10:55 |
| `ae12bb54af31227017feffd9598a6f5e` | 1 | 2026-10-20 09:08 | 2026-10-20 09:08 |


### 13.2 Extracts (SHA-256)
 
 Will be provided anonymized version 'anonymized_extracts.zip'
| File | SHA-256 |
|---|---|
| `cowrie_login_success.tsv` (797 rows) | `c81e0769804af0f90f26682cc6ee1719e526de31cf422f0c75c5d57ed113ed9e` |
| `cowrie_commands.tsv` (3 724 rows) | `c132ea03d44394c4fcf2bec003da070643a341f49b5629b126ad3de7bd4fd0bd` |
| `cowrie_downloads.tsv` (117 rows) | `f7174b26b000a3080b7b54d2270b3abe2616d54519929c6fc7e5379975f8372b` |
| `cowrie_uploads.tsv` (10 rows) | `2647dc001d968f0c32fb96a99244f429aab52d69435b4519202a6a3610cb8b22` |
| `conpot_events.tsv` (190 rows) | `03e30ddc827df9816c0e9a41e52b8b8ee0253dcde66b37a865121e82b0d9bc25` |
| `suricata_alerts_full.tsv` (33 232 rows) | *(re-generated from all rotated eve.json*)* |
| `conpot_events_full.tsv` (1 827 rows) | *(re-generated from all rotated conpot_*.json*)* |
| `dionaea_creds.jsonl` (8 632 rows) | `345336f8f6f5db2e34209637c7079981a37b2d974fc11cb26dbbda6cd38e56b2` |


---
