DEPLOYING AN INTERNET-FACING HONEYPOT - FOR THREAT INTELLIGENCE

>Under Construction
(image)

112k + Attacks in 72h

**Author:** Tiago Bastos  
**Date:** October 2026  
**Observation window:** ~48 hours (18–21 October 2026)  
**Language:** English  

> **Privacy / GDPR note**  
> All public IP addresses belonging to the author and to the honeypot virtual machine will be replaced by `x.x.x.x` in any public version of this report.  
> Attacker IPs are partially masked (first two octets retained).  
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

Operating over an exposure window of approximately 72 hours, the honeypot captured 112,000+ events recorded originating from 4,700+ distinct IP addresses. Detailed log analysis revealed high-volume attack vectors across targeted ports, primary geographic sources, and observed threat actor Tactics, Techniques, and Procedures (TTPs).

Logs were forwarded in near real-time to a Microsoft Sentinel workspace via Azure Monitor Agent and a custom Data Collection Rule (`dcr-honeypot`).  

In a ~48-hour observation window the honeypot recorded:

| Source     | Total events (approx.) | Key metric                          | Unique source IPs |
|------------|------------------------|-------------------------------------|-------------------|
| Cowrie     | ≈ 84 500               | 797 successful logins               | 150 (successful logins) |
| Dionaea    | ≈ 11 250               | 8 632 credential attempts           | 49                |
| Tanner     | ≈ 11 830               | 11 817 HTTP requests                | 204               |
| Conpot     | ≈ 1 730                | 190 OT/ICS events (local extract)   | 29                |
| Suricata   | ≈ 725 000 (all) / 4 752 alerts after filtering | 4 752 external-relevant alerts | 405               |

> **Note on Cowrie**  
> The ELK / Elasticsearch dashboard shows ≈ 84 500 Cowrie documents. These are *all* event types (session.connect, client.version, login.failed, login.success, command.input, session.closed, …).  
> Only **797** of them are `cowrie.login.success`, coming from **150 unique source IPs**.  
> The number of unique IPs that merely *connected* (without necessarily succeeding) is higher; the current evidence package contains only the top-20 by connection volume.

Custom analytic rules mapped to MITRE ATT&CK (including ATT&CK for ICS) generated alerts. Three **High** severity rules produced actionable findings that were cross-verified against the raw logs:

1. **Persistence Attempts** – ex: mass installation of SSH authorized_keys  
2. **Malware captured** – 4 confirmed samples 
3. **Payloads in POST bodies** – limited but present

Operational mitigations were required after a Conpot container was driven to 100 % CPU by a single scanner.

Total Azure cost for the period: **€15.03**.


This project demonstrates how automated entities continuously probe exposed services while proving the utility of honeypots and SIEM integration in threat research. Operational hurdles—including, port binding conflicts, and active scanning attacks that compromised Docker service stability and mitigation strategies. The total infrastructure cost incurred was approximately 15€, funded via Azure for Students credits.


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
Internet attackers
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
• Tanner – Analyzes Cowrie and Heralding logs for behavioral enrichment.
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

Twenty scheduled rules were deployed (exported as ARM template).  
Severity distribution:

- **High** – 3 rules  
- **Medium** – 12 rules  
- **Low** – 5 rules  

Full list with MITRE mapping is given in Section 7.

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
| File downloads                      | 117 (4 unique SHA-256)         |
| File uploads                        | 10                             |

> The 150 unique IPs refer **only** to sources that achieved at least one successful login.  
> The number of distinct IPs that merely opened a TCP connection (session.connect) is higher; the evidence package currently contains only the top-20 by connection volume (already > 12 000 connections from those 20 IPs alone).

**Dominant post-compromise behaviour**

- Installation of a hard-coded SSH public key (`mdrfckr`) into `~/.ssh/authorized_keys`  
- `crontab -l` and related persistence checks  
- Architecture fingerprinting (`uname`, `busybox`, CPU model strings)  
- Occasional `wget`/`curl` dropper activity  


Curled/wget IOC's
<img width="1299" height="539" alt="ksnip_20261021-195451" src="https://github.com/user-attachments/assets/79563054-5711-4f81-9bd5-bcc30bbb1e2a" />
<img width="972" height="653" alt="ksnip_20261021-195454" src="https://github.com/user-attachments/assets/5b391258-b5eb-459c-8e58-d6a9f552df1e" />



### 6.2 Conpot (OT/ICS)

| Protocol / data_type          | Events |
|-------------------------------|--------|
| IEC 104                       | 75     |
| guardian_ast                  | 70     |
| SNMP                          | 21     |
| Kamstrup protocol             | 16     |
| Kamstrup management           | 6      |
| IPMI                          | 2      |
| **Total (local extract)**     | **190** |
| Unique source IPs             | **29** |

Top scanner: `35.195.x.x` (61 events).  
(Elasticsearch total Conpot documents ≈ 1 733.)

> Some scanners driven to 100 % CPU by flooding the port 161 dropping suddently the connection.
> Mitigation: NSG deny rule of Source Malicious IP's + iptables rate-limit (100 req/30 s) + cron job that restarts the container if CPU > 75 %

image x - attack to honeypot that caused 100 cpu usage to conpot container insident.
<img width="653" height="442" alt="ksnip_20261019-101129(3)" src="https://github.com/user-attachments/assets/07a5b5c4-7962-4635-a532-e2bf687e26da" />
<img width="1200" height="912" alt="image" src="https://github.com/user-attachments/assets/e072de24-7eb6-4aca-98dc-484577e2efe2" />
The attacker flooded the machine with misconfigured GEt requestes and dropped connections, causing a Loop bug in the container that lead to 100% CPU usage.
<img width="1038" height="692" alt="ksnip_20261019-101129(4)" src="https://github.com/user-attachments/assets/db48d835-265e-44b3-ac99-e26caf8ce90c" />
<img width="987" height="705" alt="ksnip_20261019-190705" src="https://github.com/user-attachments/assets/acdf667a-93f0-4f8f-83d2-b47f55f53786" />




image x - Conpot Validation Logs response at MS defender
<img width="1140" height="816" alt="ksnip_20261018-181334" src="https://github.com/user-attachments/assets/d881e691-fd68-423d-97e2-482c6edcb59a" />


### 6.3 Dionaea

| Metric                    | Value      |
|---------------------------|------------|
| Total events (ES)         | ≈ 11 250   |
| Credential attempts       | 8 632      |
| Unique source IPs         | **49**     |

- Predominantly MySQL on port 3306 with empty passwords for `root`/`admin`/`sa`.  
- Four binary archives present;
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
| Top source IP         | 40.78.x.x (10 006 requests) – blocked - caused a CONPOT 100% CPU issue |
| Detections            | mostly `index`/`unknown`; 204 XSS, 1 RFI |

<img width="635" height="650" alt="ksnip_20261019-111116" src="https://github.com/user-attachments/assets/f2761599-b11f-4668-b3c8-1c65ebb6d7db" />
<img width="887" height="632" alt="ksnip_20261019-121448" src="https://github.com/user-attachments/assets/1504aaff-0d3b-4cec-81ce-322c568af758" />


### 6.5 Suricata

| Metric                              | Value      |
|-------------------------------------|------------|
| Total events                    | ≈ 725 000  |
| Alerts after internal filtering     | 4 752      |
| Unique source IPs (in alert extract)| **405**    |

Most relevant external signatures:

- ET SCAN Potential SSH Scan  
- ET SCAN Suspicious inbound to MySQL / MSSQL  
- ET DROP Dshield / Spamhaus  
- SSH-2.0-Go version string  
- NMAP -sS  

Image x - Validation of evidence attack on Defender from source Suricata
<img width="1130" height="738" alt="ksnip_20261019-121454" src="https://github.com/user-attachments/assets/72c85e74-f304-4d3d-bf68-9d879278fd26" />


---

## 7. Analytics Rules

All rules exclude the author’s management IP.  
Rules that produced **zero alerts** during the observation window are marked **Under evaluation** (work in progress / may need calibration).

| # | Rule name                              | Severity | MITRE tactic(s)              | Technique(s)          | Status          |
|---|----------------------------------------|----------|------------------------------|-----------------------|-----------------|
| 1 | HP - Cowrie successful login           | Low      | Initial Access               | T1078                 | Fired (noisy)   |
| 2 | Persistence Attempts                   | **High** | Persistence, Execution       | T1098.004, T1053      | **Fired – verified** |
| 3 | Dropper activity                      | Medium   | Command and Control          | T1105                 | Fired           |
| 4 | Credential reuse (T1110.004)           | Medium   | Credential Access            | T1110                 | Fired           |
| 5 | Malware captured                       | **High** | Command and Control          | –                     | **Fired – verified** |
| 6 | Credential guessing on services        | Medium   | Credential Access            | –                     | Fired           |
| 7 | OT/ICS protocol interaction            | Medium   | Reconnaissance               | T1595 (+ ICS)         | Fired           |
| 8 | Multi-port OT scanner                  | Medium   | Reconnaissance               | T1595                 | Fired           |
| 9 | Persistent OT visitor                  | Low      | Reconnaissance               | T1595                 | Under evaluation|
|10 | Same IP on SSH and OT honeypots        | Medium   | Reconnaissance               | T1595                 | Fired           |
|11 | SNMP enumeration                       | Low      | Collection                   | T1602.001             | Fired           |
|12 | SNMP flood                             | Medium   | Impact                       | T1499                 | Under evaluation|
|13 | SNMP SET attempts                      | Medium   | Collection, Impact           | –                     | Under evaluation|
|14 | web flood / fast scanner               | Medium   | Impact                       | T1499                 | Fired           |
|15 | Exploit-style paths                    | Medium   | Initial Access               | T1190                 | Fired           |
|16 | Classified web attacks                 | Medium   | Initial Access               | T1190                 | Fired           |
|17 | Payloads in POST bodies                | **High** | Execution                    | T1059                 | Under evaluation / limited |
|18 | Same IP on web and SNMP                | Medium   | Reconnaissance               | –                     | Under evaluation|

<img width="1145" height="931" alt="all rules" src="https://github.com/user-attachments/assets/e539453b-ccba-4626-9181-3fec653f807c" />

<img width="1144" height="899" alt="persistence attemp" src="https://github.com/user-attachments/assets/3076fdb3-9b69-4f26-82ce-48420a3f3a42" />

image x - Analytics Rule Sample Creation
<img width="842" height="800" alt="ksnip_20261018-172145" src="https://github.com/user-attachments/assets/028cf903-d9eb-4e95-88d6-810764190028" />
<img width="883" height="815" alt="ksnip_20261018-172145(2)" src="https://github.com/user-attachments/assets/767fa298-10e0-4514-bb3d-572dbe334ed4" />
<img width="898" height="758" alt="ksnip_20261018-172145(3)" src="https://github.com/user-attachments/assets/fa9ce220-cca1-4276-ae7d-e5922957091a" />

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

> **Screenshot placeholder**  
> <img width="1144" height="899" alt="persistence attemp" src="https://github.com/user-attachments/assets/dfe28019-4bf4-49c0-b86d-eaefcc7165bb" />

### 8.2 Malware captured (Dionaea)

- Four binary archive was retrieved by Dionaea.  

Only the cryptographic hashes are retained; the binaries themselves are kept offline and are **not** analysed further in this report.

Image x : image querie and hashes evidence by protocol.
<img width="842" height="679" alt="image" src="https://github.com/user-attachments/assets/842c5fd8-e872-496d-85cd-1303b342151c" />
Virus total evidence:
<img width="1175" height="392" alt="image" src="https://github.com/user-attachments/assets/81aa0e86-8476-4671-b818-84a080923861" />
<img width="1166" height="470" alt="image" src="https://github.com/user-attachments/assets/bd14ce0f-bc5b-429e-b01f-5670d4a5974a" />
<img width="1168" height="449" alt="image" src="https://github.com/user-attachments/assets/81341439-086a-4e49-935d-f5e9532c6e0d" />
<img width="1172" height="484" alt="image" src="https://github.com/user-attachments/assets/a9b2d71e-8620-4bb0-9087-6bf4c3f69b16" />


### 8.3 Payloads in POST bodies (T1059)

**Rule query:** looks for `base64`, `eval`, `system`, `wget`, `curl`, `exec`, `passthru` inside Tanner POST bodies.

During the observation window the volume of interesting POST bodies was low. The rule is retained and marked for further calibration on a longer dataset.

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
   - At least four successful delivery via Dionaea.

5. **Possible research / academic scanners**  
   - Some low-and-slow, multi-protocol sources that did not attempt brute-force.

6. **OpenSource Inteligence that gathers IOT divices networks**
   - Companies like Shodan retrives information that can be used for enhance security capabilities or for abuse.

The dominant motivation remains **automated compromise at scale** rather than targeted attacks against a specific organisation.

---

## 10. Challenges Encountered and Solutions

| Challenge                                      | Solution applied                                      |
|------------------------------------------------|-------------------------------------------------------|
| Conpot container driven to 100 % CPU           | NSG deny rule + iptables rate-limit (100 req/30 s) + script to evaluate container heath + cron job that restarts the container if CPU > 75 % |
| Extremely noisy “successful login” alerts      | Rule kept for visibility; grouping and suppression to be improved |
| Some analytic rules produced zero alerts       | Explicitly marked “Under evaluation” – expected on a short 48 h window |
| JSON parse errors on a subset of Tanner lines  | Defensive parsing (Python / jq with error ignoring)   |
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
2. Improve alert grouping / suppression for the “successful login” rule.  
3. Add more ICS protocols and richer Conpot templates.  
4. Automate the evidence packaging (SHA-256 manifest + selective log extracts).  
5. Overlay the observed techniques on the MITRE ATT&CK Navigator (including the ICS matrix).  

The project already provides a solid, recruiter-friendly artefact that shows hands-on experience with honeypots, Azure Sentinel, detection engineering and privacy-aware research.

---

## 13. Appendix – Evidence Index & Chain of Custody



---
