# DEPLOYING AN INTERNET-FACING HONEYPOT – THREAT INTELLIGENCE

<img width="1408" height="768" alt="Gemini_Generated_Image_3b2jml3b2jml3b2j" src="https://github.com/user-attachments/assets/d3e0310f-a9b9-44f0-9b33-e72218e83f64" />

# 112k events in 72 h · 2,100+ unique IPs

**Author:** Tiago Bastos  
**Date:** October 2026  

---

## TABLE OF CONTENTS

1. [Executive Summary](#1-executive-summary)
2. [Project Objectives](#2-project-objectives)
3. [Environment & Architecture](#3-environment--architecture)
4. [Honeypot Deployment Walkthrough](#4-honeypot-deployment-walkthrough)
5. [Microsoft Sentinel Deployment](#5-microsoft-sentinel-deployment)
6. [Log Analysis & Key Findings](#6-log-analysis--key-findings)
7. [Analytics Rules](#7-analytics-rules)
8. [Verified High-Severity Cases (Evidence from Logs)](#8-verified-high-severity-cases-evidence-from-logs)
9. [Who Are the Attackers? Why?](#9-who-are-the-attackers-why)
10. [Challenges Encountered and Solutions](#10-challenges-encountered-and-solutions)
11. [Cost Breakdown](#11-cost-breakdown)
12. [Conclusion & Recommendations](#12-conclusion--recommendations)
13. [References](#13-references)

---

## 1. Executive Summary

An internet-facing T-Pot all-in-one honeypot (only used Cowrie, Conpot, Dionaea, Tanner, Suricata) ran for ~72 hours on Azure and fed Microsoft Sentinel through the Azure Monitor Agent and a custom DCR. It recorded ~112k honeypot events plus 18.6k external Suricata alerts. The traffic was dominated by SSH botnets (backdoor key installed 77 times from 41 IPs), one Azure-hosted scanner that flooded the web, SNMP and IDS sensors and crashed a Conpot container, and a smaller amount of OT/ICS probing. Created 22 KQL analytic rules mapped to MITRE ATT&CK (Enterprise and ICS) raised 5,428 alerts; the 72-hour evaluation also exposed noise, repeated alerts and misconfigured rules, documented here as improvements. Total cost: about €15.

This report documents the deployment, integration and analysis of an internet-facing T-Pot honeypot on Microsoft Azure (Spain Central). Five services ran for approximately 72 hours (18–21 October 2026):

- **Cowrie** – SSH/Telnet medium-interaction honeypot
- **Conpot** – ICS/OT protocols (IEC 104, SNMP, Kamstrup, …)
- **Dionaea** – low-interaction malware capture (FTP, MySQL, SMB, …)
- **Tanner** – web application honeypot
- **Suricata** – network IDS, plus a local ELK stack for visualisation and comparison

Logs were forwarded in near real time to a Microsoft Sentinel workspace through the Azure Monitor Agent and a custom Data Collection Rule (`dcr-honeypot`), where 22 scheduled KQL analytic rules, mapped to MITRE ATT&CK (Enterprise and ICS), generated alerts.

**What was observed (18–21 October 2026)**

| Source | Events | Key metric | Unique source IPs |
|---|---|---|---|
| Cowrie | ≈ 84 500 | 797 successful logins; `mdrfckr` key installed 77 times | 150 (successful logins) |
| Dionaea | ≈ 11 250 | 8 632 credential attempts (99.6 % MySQL); 4 malware files, 1 trojan | 49 |
| Tanner | ≈ 11 830 | 11 817 HTTP requests, 85 % from one IP | 204 |
| Conpot | 1 545 (+ 282 author test events, excluded) | SNMP 555 · Kamstrup 454 · guardian_ast 318 · IEC 104 192 | 202 |
| Suricata | **18 586** external alerts (33 232 raw) | DoublePulsar (4 IPs), SSH scans, SNMP, log4j, web scans | 1 493 |

<img width="840" height="500" alt="ksnip_20261022-020758(4)" src="https://github.com/user-attachments/assets/f22b2df7-788c-403a-ae79-d76e38d2ae80" />

> **How the headline numbers are built.** "112k events" is the sum of the honeypot documents in Elasticsearch: Cowrie 84 502 + Tanner 11 831 + Dionaea 11 250 + SentryPeer 2 617 + Conpot 1 733 + Dicompot 48 = 111 981. Suricata, P0f, Fatt and NGINX records are not included.  
> The 797 successful Cowrie logins come from 150 unique IPs; the number of IPs that merely connected is higher.

**Key findings**

- **SSH botnets dominate.** The same hard-coded SSH key (`mdrfckr`) was installed 77 times from 41 IPs, and one IP alone made 454 of the 797 successful logins.
- **One Azure-hosted scanner (`40.78.x.x`)** produced 10 006 web requests, 402 Conpot events and 4 008 Suricata alerts within about 30 minutes on 19 October. Together with three other sources it drove the Conpot container to 100 % CPU, which required mitigation (6.2.1).
- **OT/ICS probing** hit SNMP, Kamstrup, guardian_ast and IEC 104, usually in short single-protocol bursts.
- **Malware:** Dionaea captured four distinct files, one identified as a trojan.
- **Detection engineering:** 20 of the 22 rules fired (5,428 alerts, none promoted to an incident). Three High-severity rules (Persistence Attempts, Malware captured, Payloads in POST bodies) were cross-checked against the raw logs. As a deliberately short evaluation, the run also showed noise, repeated alerts and misconfigured rules, which are documented in 7.1 and listed as improvements.

**Cost** 

The whole infrastructure cost about €15, funded with Azure trial credits.

**Privacy / GDPR note**  
All public IP addresses belonging to the author and to the honeypot virtual machine are anonymized (`x.x.x.x`) in the public version of this report.  
Attacker IPs are partially masked (first two octets retained for easier reading of the evidence).  
Credential lists and command histories are retained because they represent common attacker behaviour observed on an intentionally exposed research system.  
No malware binaries are published, only cryptographic hashes.
> GDPR explicitly classifies online identifiers, including both static and dynamic IP addresses, as personal data. 


## 2. Project Objectives

The primary goals of this project were:
- **Deploy Cloud Infrastructure:** Provision an internet-facing Linux host on Microsoft Azure running the T-Pot framework.
- **Simulate Exposed Targets:** Emulate vulnerable services across multiple protocols (SSH, HTTP, SMB) with a primary focus on ICS/SCADA environments (e.g., using Conpot alongside Cowrie and Suricata) to capture unsolicited internet traffic.
- **Establish SIEM Ingestion:** Build custom ingestion pipelines and connectors to stream logs from local containerized services to Microsoft Sentinel.
- **Threat Detection & KQL Rules:** Construct custom Kusto Query Language (KQL) analytics rules focusing on MITRE ATT&CK TTPs, brute-force patterns, and targeted probing of industrial control protocols.
- **Document Technical Challenges:** Identify and resolve deployment friction points, such as Docker container orchestration, port conflicts, and disabling active modules (e.g., SpiderFoot) to avoid unwanted outbound scanning reports.
- **Deliver Cost-Aware Intelligence:** Produce an actionable threat intelligence report mapping real-world threat actor behaviors while maintaining cost controls.
- **Ensure Regulatory Compliance:** Practice privacy-by-design by anonymizing/obfuscating IPv4/IPv6 data to align with GDPR guidelines prior to publishing findings.


## 3. Environment & Architecture

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
| Data collection rule | `dcr-honeypot`|
| Public IP | *anonymised as x.x.x.x in public version*  |

### 3.2 Network Security Group (NSG)

Management ports (64294, 64295, 64297) were restricted to privite IP only.  

Honeypot ports (expanded set used during the experiment):

**TCP:** 20, 21, 22, 23, 42, 80, 81, 135, 443, 445, 502, 1025, 1433, 1723, 1883, 2404, 3306, 3389, 5555, 5900, 6379, 9200, 9300, 10001, 11112, 11211, 27017, 44818, 47808, 50100  

**UDP:** 69, 123, 161, 623, 1900, 5000, 5060, 5353  

A temporary deny rule (`block-attack1`) was added for four aggressive source IPs after a Conpot CPU exhaustion incident.

<img width="996" height="504" alt="image" src="https://github.com/user-attachments/assets/e7bb952e-8a5c-409e-bef5-9d9f7e9ba6dd" />


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

> The commands used for the T-Pot installation and the Azure VM provisioning are not reproduced here; follow the official T-Pot installation guide (see [References](#13-references)).

The honeypot is a default T-Pot installation with a few custom modifications. Not every T-Pot capability was used, and SpiderFoot was removed completely to avoid automatic outbound scans.

The stack was adjusted to expose these services:

- **Cowrie** – emulates SSH and Telnet to capture login attempts and shell interactions.
- **Conpot** – simulates industrial control systems (ICS/SCADA) to attract infrastructure-targeted attacks.
- **Dionaea** – collects malware by mimicking vulnerable services such as SMB, HTTP and FTP.
- **Suricata** – network intrusion detection system that analyzes and logs malicious traffic.
- **Tanner** – web application honeypot that emulates vulnerable web apps and classifies HTTP requests (index, XSS, RFI, CRLF, WordPress probes).
- **Nginx** – management and Kibana dashboards.

A custom Network Security Group (NSG) exposes only the ports required by these services (see 3.2).

*Figure: ELK dashboard (statistics after 72 h)*

<img width="1597" height="835" alt="ksnip_20261021-145137" src="https://github.com/user-attachments/assets/6ee22593-2d85-4ccb-880e-3212d9d1dedb" />

<img width="1593" height="687" alt="ksnip_20261021-145137(2)" src="https://github.com/user-attachments/assets/45a5c64b-96d0-4214-b0fd-c93ee80bb1dd" />

<img width="1593" height="444" alt="ksnip_20261021-145137(3)" src="https://github.com/user-attachments/assets/48b11490-353d-419d-8a92-57fbb7577c68" />

---


## 5. Microsoft Sentinel Deployment

The Sentinel installation is not reproduced here; follow the official Microsoft documentation (see [References](#13-references)). The figures below show the validation of the Azure Monitor Agent (AMA) installation and of the DCR required to forward the logs of a Linux machine to a Log Analytics workspace in another resource group.

*Figure: AMA Install in RG*

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

Twenty of the 22 rules produced alerts (5,428 in total, none promoted to an incident); two produced none. Full list with MITRE mapping is in Section 7.

<img width="1217" height="928" alt="ksnip_20261019-105529" src="https://github.com/user-attachments/assets/64bb06c9-3ce0-4dad-a58a-c48ada90ddbe" />


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


** Cowrie downloads (SHA-256)**

| SHA-256 | Events | Source IPs | First / last seen (UTC) | Context |
|---|---|---|---|---|
| `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` | 77 | 41 | 2026-10-20T22:55 / 2026-10-21T12:59 | `mdrfckr` playbook (chattr, authorized_keys, chpasswd): the SSH key file |
| `01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b` | 36 | 23 | 2026-10-21T00:21 / 2026-10-21T12:59 | same playbook (`secure.sh` / `auth.sh` clean-up); not a binary download |
| `0db4656687a425c47d19000db866db52c7e415dbfaf6b5c651adcb9275ab23ca` | 2 | 1 | 2026-10-20T03:41 / 2026-10-20T10:57 | one IP, `uname -a; echo -e "\x61\x75..."; cd /tmp` |
| `ae8d459595257f2f22c9d1ff74c4fb8a91643fad7899b57556496716692b904e` | 2 | 1 | 2026-10-20T03:41 / 2026-10-20T10:57 | same IP and same two sessions as `0db46566` |


*Figure: botnet-style TTPs*

<img width="730" height="137" alt="image" src="https://github.com/user-attachments/assets/a4ab114e-eb67-4204-8f54-735fca550f73" />


*Figure: curl / wget IOCs*

<img width="1299" height="539" alt="image" src="https://github.com/user-attachments/assets/2e02dbc4-d5f1-4d5e-bfe5-6ece890c5a0a" />

<img width="972" height="653" alt="image" src="https://github.com/user-attachments/assets/89ca3381-8e5d-4592-91ab-d2eaa2ab6a98" />



### 6.2 Conpot (OT/ICS)

Every rotated Conpot log (`conpot_*.json*`, 18–21 October 2026) holds **1 827 events from 203 source IPs**. 282 of them come from the author's own validation test (18 Oct 15:36–15:39 UTC, figure below) and are excluded, leaving **1 545 attacker events from 202 IPs**.  
Daily volume (attackers only): 18 Oct 308 · 19 Oct 771 · 20 Oct 275 · 21 Oct 191.

| Protocol (`data_type`) | Port | Events | Source IPs | Protocol requests | MITRE ATT&CK for ICS | Sentinel rules that cover it |
|---|---|---|---|---|---|---|
| SNMP (`snmp`) | 161/udp | **555** | 50 | 555 (`SNMPv2 Get` 401, `Bulk` 61, `GetNext` 45, `SNMPv1 Get` 44, `GetNext` 3, `SNMPv2 Set` 1) | T0888 (T1602.001 Enterprise) | SNMP enumeration, SNMP flood, SNMP SET attempts |
| Kamstrup protocol (`kamstrup_protocol`) | 1025/tcp | **325** | 49 | 4 | T0883, T0846 | OT/ICS protocol interaction, Multi-port OT scanner |
| Guardian AST (`guardian_ast`) | 10001/tcp | **318** | 85 | 20 (`AST I20100` 14, `AST i90200` 6) | T0883, T0846 | OT/ICS protocol interaction |
| IEC 60870-5-104 (`IEC104`) | 2404/tcp | **192** | 30 | 0 | T0883, T0846 | OT/ICS protocol interaction, Multi-port OT scanner |
| Kamstrup management (`kamstrup_management_protocol`) | 50100/tcp | **129** | 14 | 30 | T0883, T0846 | OT/ICS protocol interaction |
| IPMI (`ipmi`) | 623/udp | **22** | 7 | 6 (`GET_CHANNEL_AUTH_CAPABILITIES`) | T0888 | OT/ICS protocol interaction |
| EtherNet/IP (`enip`) | 44818/tcp | **4** | 1 | 0 | T0883, T0846 | OT/ICS protocol interaction |
| **Total (attackers)** | | **1 545** | **202** | **615** | | |

Of the 1 545 attacker events, 930 are connection open/close events and 615 carry a protocol request. SNMP is the only protocol where every event is a request.

| Top sources | Events | Notes |
|---|---|---|
| `40.78.x.x` | 402 | 391 SNMP requests in 24 minutes (19 Oct 08:07–08:32 UTC), including the **only `SNMPv2 Set`** of the dataset (08:08:34). Also the top Tanner and Suricata source; blocked afterwards |
| `178.166.x.x` | 245 | 2-minute multi-protocol burst on 18 Oct (17:23–17:25 UTC): Kamstrup management 81, Kamstrup 72, IEC 104 48 |
| `35.195.x.x` | 61 | IEC 104 only, within one minute on 21 Oct (07:23 UTC); Google Cloud range |
| `165.154.x.x` | 26 | Kamstrup only, 19 Oct 04:05 UTC |
| `3.129.x.x` / `18.218.x.x` | 24 each | AWS-range scanners (Kamstrup / multi-protocol) |

Cross-check with Sentinel (alerts over the full ~72 h): OT/ICS protocol interaction 857 alerts / 156 IPs, Same IP on SSH and OT honeypots 211 / 12, Multi-port OT scanner 84 / 5, Persistent OT visitor 7 / 5, SNMP flood 6 / 1, SNMP enumeration 2 / 2, SNMP SET attempts 2 / 1, Same IP on web and SNMP 20 / 1. The SNMP flood, SNMP SET and web-and-SNMP rules each name a single IP, which matches the `40.78.x.x` burst above.

*Figure: author validation test against the Conpot sensor (Siemens PLC emulation, 18 Oct, excluded from the statistics)*

<img width="1140" height="816" alt="ksnip_20261018-181334" src="https://github.com/user-attachments/assets/db541aca-0ba0-40fc-ba6d-302419659c8f" />

### 6.2.1 Conpot 100 % CPU Incident

**Impact.** Four sources, each in turn, drove the Conpot container to 100 % CPU. While the container was pegged, Conpot stopped answering, so the sensor was blind to OT traffic until it was restarted.

**Trigger.** Floods on **port 80 (HTTP)** and **port 161 (SNMP)**: malformed GET requests and SNMP requests whose connections were dropped mid-request. The container entered a loop and kept a core at 100 % without needing further traffic. In the logs, the port 80 requests appear in Tanner and Suricata, and the SNMP requests in Conpot and Suricata.

**Sources (all later added to the NSG `block-attack1` deny rule):**

| Source | Evidence in the logs (UTC) |
|---|---|
| `40.78.x.x` | 19 Oct 08:07–08:38. Tanner: **10 006** requests (peak 2 068 req/min, 5 819 distinct paths). Conpot: **402** events (391 SNMP, one `SNMPv2 Set`). Suricata: **4 008** alerts (3 173 on port 80, 813 on port 161). Azure address space (an Azure-hosted scanner) |
| `189.150.x.x` | Cowrie: **1 144** `session.connect`; Suricata: 48 alerts (SSH scan, 19 Oct 10:13–10:50); one Cowrie login at 10:13:59. No Conpot events |
| `66.132.x.x` | 19 Oct 15:34:16: 4 EtherNet/IP events on Conpot and 1 Suricata alert (Dshield list). Censys scanner range |
| `77.110.x.x` | No event in any sensor log; the evidence for this source is the CPU screenshots |

The same IP (`40.78.x.x`) dominates three sensors at once, which is why a single source could both exhaust Conpot and generate the bulk of the Tanner and Suricata volume.

*Figure: attack against the honeypot that caused the 100 % CPU usage of the Conpot container*

<img width="653" height="442" alt="ksnip_20261019-101129(3)" src="https://github.com/user-attachments/assets/07a5b5c4-7962-4635-a532-e2bf687e26da" />

<img width="1200" height="912" alt="image" src="https://github.com/user-attachments/assets/e072de24-7eb6-4aca-98dc-484577e2efe2" />

The attacker flooded the machine with malformed GET requests and dropped connections, causing a loop bug in the container that led to 100 % CPU usage.

<img width="1038" height="692" alt="ksnip_20261019-101129(4)" src="https://github.com/user-attachments/assets/db48d835-265e-44b3-ac99-e26caf8ce90c" />

<img width="987" height="705" alt="ksnip_20261019-190705" src="https://github.com/user-attachments/assets/acdf667a-93f0-4f8f-83d2-b47f55f53786" />

**Timeline** (log-derived rows in UTC; CPU spikes and NSG times to be completed from the screenshots and `az monitor activity-log`):

| Step | Time (UTC) | Evidence |
|---|---|---|
| `40.78.x.x` first SNMP request on Conpot | 19 Oct 08:07:54 | Conpot log |
| `40.78.x.x` flood on Tanner | 19 Oct 08:08:05–08:38:20 | Tanner log |
| Only `SNMPv2 Set` in the dataset | 19 Oct 08:08:34 | Conpot log |
| `189.150.x.x` SSH scan | 19 Oct 10:13–10:50 | Suricata, Cowrie |
| `66.132.x.x` EtherNet/IP probe | 19 Oct 15:34:16 | Conpot, Suricata |
| First CPU spike | TBD | screenshot |
| First source blocked in `block-attack1` | TBD | activity log |
| Second, third, fourth spikes and blocks | TBD | screenshots |
| Final mitigation in place (iptables + watchdog) | TBD | cron / iptables |

**Why the block list alone failed.** Each new scanner re-triggered the bug. Blocking by source is reactive and always one incident behind.

**Layered fix.**

1. NSG deny rule for the offending sources (reactive).
2. iptables rate limit, dropping after 100 requests in 30 s.
3. A watchdog (cron plus script) that restarts the container when CPU exceeds 75 %.

**Future improvements:** a Docker CPU limit on the Conpot container, a container health check, and an Azure Monitor alert on CPU so the first incident is detected automatically.

*Figure: NSG with the updated block list*

<img width="1055" height="342" alt="image" src="https://github.com/user-attachments/assets/0eea8996-96fe-49fc-9d93-2bb17841eec9" />


### 6.3 Dionaea

| Metric                    | Value      |
|---------------------------|------------|
| Total events (ES)         | ≈ 11 250   |
| Credential attempts       | 8 632      |
| Unique source IPs         | **49**     |

- Predominantly MySQL on port 3306 with empty passwords for `root`/`admin`/`sa`.  
- Credential attempts by service: MySQL 8,594 (port 3306), MSSQL 32 (1433), FTP 6 (21). Usernames `root`, `sa` and `admin` account for about 2,900 attempts each; 8,616 of the 8,632 passwords are empty.
- Four distinct malware files were captured (MD5 values in 8.2); one was identified as a trojan on VirusTotal. In the evidence package `binaries.tgz` is empty and only `binaries.tgz.1` and `.2` hold data.
- Only cryptographic hashes are retained for the report.

*Figure: VirusTotal report*

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

| Metric | Value |
|---|---|
| Total events (ES) | ≈ 725 000 |
| Alerts, raw (all rotated `eve.json*`, 18 Oct 12:39 to 21 Oct 13:33 UTC) | **33 232** |
| – internal / Azure platform sources (`10.10.0.4` 12 768, `169.254.169.254` 729, `168.63.129.16` 693) | 14 190 |
| – author management IP | 456 |
| **External alerts** | **18 586** |
| Unique external source IPs | **1 493** (1 497 including the three internal addresses and the author) |
| External alerts per day (18 / 19 / 20 / 21 Oct) | 1 355 / 8 075 / 6 602 / 2 554 |
| External alerts by severity (1 / 2 / 3) | 6 990 / 6 811 / 4 785 |

> Full re-parse of `eve.json` plus `eve.json.1.gz` … `eve.json.5.gz`.  
> The internal rows are the honeypot's own traffic and Azure platform chatter: all 8 696 "HTTP Request on Unusual Port", 1 090 "GPL TELNET Bad Login" and 465 "BusyBox Banner Observed" come from them, so they are not attacker activity.  
> The DCR transform drops alerts whose source is `10.10.0.4` or whose destination is an Azure platform address. Alerts where a platform address is the *source* are not covered by that filter, so the Sentinel counts should be checked against `SuricataAlerts_CL` before comparing them with this table.

**Top signatures, external sources only**

| Count | Signature |
|------:|---|
| 4 558 | ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| 1 229 | ET INFO SSH session in progress on Expected Port |
| 1 205 | ET INFO SSH-2.0-Go version string Observed in Network Traffic |
| 711 | ET DROP Dshield Block Listed Source group 1 |
| 628 | GPL SNMP request udp |
| 592 | ET SCAN Potential SSH Scan |
| 571 | GPL SNMP public access udp |
| 531 | GPL INFO PPTP Start Control Request attempt |
| 477 | ET SCAN NMAP -sS window 1024 |
| 458 | ET HUNTING Possible Apache log4j RCE Attempt (CVE-2021-44228) |
| 435 | ET SCAN Suspicious inbound to mySQL port 3306 |
| 266 | ET SCAN Sipsak SIP scan |
| 133 | ET SCAN Suspicious inbound to MSSQL port 1433 |

Most targeted ports (external alerts): 445 (4 757), 80 (4 570), 22 (4 238), 161 (1 292), 1723 (694), 3306 (648), 23 (412), 5060 (343).

**Top external sources **

| Alerts | Source | Notes |
|---:|---|---|
| 4 008 | `40.78.x.x` | 19 Oct 08:07–08:37 UTC only: port 80 (3 173), SNMP 161 (813), all 1 271 log4j-related alerts. Also flooded Tanner and Conpot; later blocked |
| 1 575 | `196.190.x.x` | DoublePulsar on port 445, 20 Oct 09:10–09:14 |
| 1 507 | `176.211.x.x` | DoublePulsar on port 445, 20 Oct 07:25–07:28 |
| 1 435 | `129.205.x.x` | DoublePulsar on port 445, 19 Oct 16:33–16:38 |
| 529 | `93.123.x.x` | PPTP (port 1723) probes and Spamhaus DROP hits, spread over 19–21 Oct |
| 267 | `31.7.x.x` | SIP scan (Sipsak, port 5060), 19 Oct 08:39–08:40 |
| 246 / 213 | `77.239.x.x` (two IPs) | SSH scans (Go client); also heavy on Cowrie |
| 221 | `77.90.x.x` | MySQL scan (port 3306), 19–21 Oct |

Notable findings: **DoublePulsar** is the most frequent signature, but 4 501 of its 4 558 alerts come from only three IPs, each in a single burst of 3 to 5 minutes on port 445. The 458 log4j alerts (1 271 across all log4j signatures) come from a single IP, the same Azure-hosted scanner as above.

*Figure: validation in Defender of an attack seen by Suricata*

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
| 12 | SNMP flood | Med | Impact | T1498.001 | T0814 | 6 | 1 | Fired, matches the 391-request SNMP burst (6.2) |
| 13 | SNMP SET attempts | Med | Collection, Impact | T1565.001 (to confirm) | T0836 | 2 | 1 | Fired, matches the single `SNMPv2 Set` (19 Oct 08:08:34 UTC) |
| 14 | Web flood / fast scanner | Med | Impact | T1499.002 | n/a | 477 | 4 | Fired, noisy |
| 15 | Exploit-style paths | Med | Initial Access | T1190 | n/a | 150 | 17 | Fired |
| 16 | Classified web attacks | Med | Initial Access | T1190 | n/a | **0** | n/a | Under evaluation (no alert) |
| 17 | Payloads in POST bodies (v2) | **High** | Initial Access, Execution | T1190, T1059, T1105, T1552.001 | n/a | 156 | 1 | v1 fired; rewritten as v2, needs re-evaluation |
| 18 | Same IP on web and SNMP | Med | Reconnaissance | T1595.002 | T0846 | 20 | 1 | Fired, matches `40.78.x.x` |
| 19 | Same IP on SSH and Dionaea | Low | Reconnaissance | T1595 | n/a | 205 | 13 | Fired  |
| 20 | Multi-service scanner | Med | Reconnaissance | T1595.001, T1046 | n/a | **0** | n/a | Under evaluation  |
| 21 | SMB/RPC scanning | Low | Lateral Movement (as configured) | T1210, closer to T1595 for inbound scans | n/a | 19 | 17 | Fired  |
| 22 | Database probing | Med | Initial Access | T1190, T1110.001 | n/a | 54 | 20 | Fired |

<img width="1145" height="931" alt="all rules" src="https://github.com/user-attachments/assets/e539453b-ccba-4626-9181-3fec653f807c" />

<img width="1144" height="899" alt="persistence attemp" src="https://github.com/user-attachments/assets/3076fdb3-9b69-4f26-82ce-48420a3f3a42" />

*Figure: Analytics Rule Sample Creation*

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

*Figure: sample query*

<img width="1054" height="706" alt="image" src="https://github.com/user-attachments/assets/61004b0c-6762-4936-ae82-01b93cf96343" />


### 8.2 Malware captured (Dionaea)

- Four distinct files were captured by Dionaea; one was identified as a trojan.

Only the cryptographic hashes are retained; the binaries themselves are kept offline and are **not** analysed further in this report.

| MD5 | Alerts | First seen (UTC) | Last seen (UTC) |
|---|---|---|---|
| `70ccd9220cebb56eaa38b9f1bd1a1cd8` | 6 | 2026-10-19 22:08 | 2026-10-20 03:09 |
| `33d373e264dc7fdb0bcdbd8e075a6319` | 3 | 2026-10-19 21:08 | 2026-10-19 23:09 |
| `bedea9a1132892eb9041c601f2a49d03` | 2 | 2026-10-20 10:25 | 2026-10-20 10:55 |
| `ae12bb54af31227017feffd9598a6f5e` | 1 | 2026-10-20 09:08 | 2026-10-20 09:08 |

These values come from the *Malware captured* alerts. They are not the SHA-256 values found in the Cowrie files (a different artefact), and `binaries.tgz` in the evidence package is the hash of an empty file.

*Figure: query and hash evidence by protocol*

<img width="842" height="679" alt="image" src="https://github.com/user-attachments/assets/842c5fd8-e872-496d-85cd-1303b342151c" />

*Figure: VirusTotal evidence*

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

<img width="635" height="650" alt="ksnip_20261019-111116" src="https://github.com/user-attachments/assets/9feb9dcb-d029-4b84-a4a4-321d74dc4cd5" />


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
   - One Azure-hosted IP alone generated 10 006 requests in 30 minutes.  
   - Classic credential stuffing and vulnerability scanning.

3. **OT/ICS reconnaissance**  
   - Probes against SNMP, Kamstrup, guardian_ast, IEC 104, IPMI and EtherNet/IP (1 545 events from 202 IPs).  
   - Low volume, usually short single-protocol bursts, but of high interest for industrial threat intelligence.

4. **Malware distribution**  
   - Four distinct malware files captured by Dionaea, one identified as a trojan.

5. **SMB / DoublePulsar-style probing**
   - Suricata recorded **4 558** alerts for "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication", the most frequent external signature, but from only **four source IPs** (three of them produced 4 501 alerts, each in a single burst of 3 to 5 minutes on port 445).
   - This is consistent with automated SMB backdoor-check tooling run by a few hosts, not with a widespread campaign.

6. **Possible research / academic / OSINT scanners**  
   - Some low-and-slow, multi-protocol sources that did not attempt brute-force.  
   - Internet-wide scanners (e.g. Censys-range `66.132.x.x`, Shodan-style probes) that map exposed IoT and ICS devices; the data can be used for defence or for abuse.

The dominant motivation remains **automated compromise at scale** rather than targeted attacks against a specific organisation.

---

## 10. Challenges Encountered and Solutions

| Conpot container driven to 100 % CPU           | NSG deny rule + iptables rate-limit (100 req/30 s) + script to evaluate container heath + cron job that restarts the container if CPU > 75 % |
| Extremely noisy “successful login” alerts      | Rule kept for visibility; grouping and suppression to be improved |
| Some analytic rules produced zero alerts       | Explicitly marked “Under evaluation” (Classified web attacks, Multi-service scanner) – expected on a short ~72 h window |
| Repeated alerts (same event alerted in every overlapping run) | Documented in 7.1; fix by setting lookback equal to frequency, grouping by entity and summarising per entity |
| Conpot / Suricata initially under-counted | First extracts used only the current log file; a full re-parse of all rotated `.json*` files raised Conpot to 1 827 events (1 545 excluding the author) and Suricata to 33 232 raw alerts (18 586 external) |


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
No budget alerts were configured. A daily ingestion limit of 8 GB was applied to the workspace.

---

## 12. Conclusion & Recommendations

The ~72-hour experiment successfully demonstrated:

- End-to-end telemetry pipeline from Internet-facing honeypots into Microsoft Sentinel.  
- Detection of real-world persistence, credential stuffing, OT reconnaissance and malware delivery.  
- Practical operational hardening under live attack.

**Recommendations for a future follow-up engagement**

1. Extend the observation window to 7–14 days to give low-volume rules a chance to fire.  
2. Improve alert grouping / suppression for the “successful login” rule and for every rule with a lookback longer than its frequency (see 7.1).
   - Fix the two entity mappings (Credential reuse, Malware captured), add MITRE techniques to the rules that have none, and calibrate the two silent rules.
   - Put limits on the Conpot container (CPU limit, health check, Azure Monitor CPU alert).  
3. Add more ICS protocols and richer Conpot templates.  
4. Automate the evidence packaging (SHA-256 manifest + selective log extracts).  
5. Overlay the observed techniques on the MITRE ATT&CK Navigator (including the ICS matrix).  

The 22 rules were an evaluation run of ~72 hours: some alerts are noise, repeats or the product of misconfigured rules, and that is part of the findings rather than a defect of the data.

The project provides a solid, friendly artefact that demonstrates hands-on experience with honeypots, Azure Sentinel, detection engineering and treath research.

---

## 13. References

1. **T-Pot** – Deutsche Telekom Security, multi-honeypot platform: <https://github.com/telekom-security/tpotce>
2. **Microsoft Azure** – Network security groups overview: <https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview>
3. **Microsoft Sentinel** – What is Microsoft Sentinel SIEM?: <https://learn.microsoft.com/en-us/azure/sentinel/overview>
4. **Microsoft Defender XDR** – What is Microsoft Defender XDR?: <https://learn.microsoft.com/en-us/defender-xdr/microsoft-365-defender>

---
