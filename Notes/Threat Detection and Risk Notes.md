# Threat Detection Notes

**Complete Module - Risk Management + Threat Detection**

Includes: Risk Management | Assessment | Threats | Wazuh | FIM | IDS | WAF | YARA | SOC | Architectures

---

## PART 1: RISK MANAGEMENT

### 1. Fundamental Concepts of Risk

#### 1.1. Definitions of Risk

*   **Risk (Cybersecurity):** Probability of a vulnerability being exploited by a threat.
*   **Risk (ISO):** Effect of uncertainty on objectives. It focuses on the impact of incomplete knowledge of events or circumstances on an organization's decision-making process.

**Components of Risk:**
*   **Vulnerability:** Weakness in a system or security configuration.
*   **Threat:** Event, agent, or action that can exploit vulnerabilities (e.g., hackers, malware, insider attacks, negligent employees).
*   **Impact:** Consequences and damage resulting from a security incident.

**Fundamental Principle:** Reducing threats or vulnerabilities reduces risk.

#### 1.2. What are Threats

Threats represent any event, agent, or action that can exploit vulnerabilities and cause harm to systems, data, or people.

##### 1.2.1. Threat Actors

**Black Hats (Malicious Hackers)**
*   Individuals who exploit system vulnerabilities with illegal or destructive intent.
*   They can steal data, install malware, or cause damage to infrastructure.
*   **Motivations:** Financial gain, espionage, reputation in the cybercrime community.

**Employees**
*   Current employees can represent an accidental or intentional threat.
*   Cause incidents through human error, negligence, or violation of internal policies.
*   **Examples:** Improper sharing of credentials, loss of corporate devices, clicking on phishing emails.

**Insider Threats / Sabotage**
*   People with authorized access who deliberately use that access to cause harm or compromise the organization.
*   Can include internal espionage, data theft, or system destruction.
*   Difficult to detect because the attacker already has legitimate permissions.

### 2. Risk Management

#### 2.1. Definition and Objectives

**Definition:** Risk Management is the process of eliminating as much risk as possible and limiting the effects of risks that cannot be fully eliminated.

**Objectives of Risk Management:**
*   Identify factors or threats that can cause harm.
*   Evaluate factors based on the value of assets and existing countermeasures.
*   Implement economically viable solutions to reduce risk.
*   Maintain a secure environment through continuous monitoring.

#### 2.2. Types of Risk Management

*   **Risk Management Sessions:** Meetings where what can go wrong with assets is discussed.
*   **Compliance Risk Management:** Alignment with standards, regulations, and legal requirements.
*   **Technical/Vulnerability Risk Management:** Identification and correction of technical risks or flaws in operating systems.
*   **Threat Monitoring Risk Management:** Continuous monitoring of the environment to detect potential threats.

#### 2.3. Roles in Risk Management

**Risk Manager**
*   Leadership role in the risk management process.
*   Responsible for establishing the risk management framework.
*   Coordinates all phases: identification, analysis, evaluation, treatment, and monitoring of risks.
*   Communicates with management and ensures alignment between risks and strategic objectives.
*   Supervises the implementation of mitigation plans and ensures compliance with standards (ISO 27005, NIST RMF).

**Risk Owner**
*   Responsible for accepting or mitigating risks under their responsibility.
*   Has the authority to make decisions about the treatment of specific risks.
*   Typically a manager or director of the area affected by the risk.

**Risk Management Specialist**
*   Provides technical and methodological expertise.
*   Supports the Risk Manager in implementing processes and frameworks.

**Subject Matter Experts (SME)**
*   Identify risks in their areas of technical expertise.
*   Propose specific technical recommendations for mitigation.
*   Examples: Network, security, infrastructure, and application specialists.

### 3. Risk Assessment

#### 3.1. Assessment Process

**Risk Identification:**
Identification must consider:
*   Business processes and dependencies.
*   Technological and human vulnerabilities.
*   Critical data and systems.
*   History of incidents and known threats.

**Analysis and Evaluation:**
*   **Likelihood:** How likely an event is to occur.
*   **Impact:** Estimate of the damage caused by an event.
*   **Risk Assessment:** Combination of likelihood and impact to determine the level of risk.

#### 3.2. Likelihood Rating

| Level | Classification | Frequency |
| :--- | :--- | :--- |
| 1 | Very Unlikely | Occurs once every 5 years |
| 2 | Unlikely | Occurs once every 3 years |
| 3 | Likely | Occurs once a year |
| 4 | Very Likely | Occurs a few times a year |
| 5 | Highly Likely | Occurs every month |

#### 3.3. Impact Rating

| Level | Classification | Description |
| :--- | :--- | :--- |
| 1 | Insignificant | Asset loss less than €5,000 |
| 2 | Minor | Loss between €5,000 and €25,000 |
| 3 | Moderate | Loss between €25,000 and €50,000 |
| 4 | High | Loss greater than €50,000 |
| 5 | Catastrophic | Affects company reputation, legal fines, or loss of license |

#### 3.4. Risk Rating Matrix

The risk matrix combines Likelihood × Impact to determine the risk level:

**Classification:**
*   1-7 → Low Risk
*   7-17 → Medium Risk
*   17-25 → High Risk

| Likelihood \ Impact | 1 | 2 | 3 | 4 | 5 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1 - Very Unlikely** | Low | Low | Low | Low | Low |
| **2 - Unlikely** | Low | Low | Low | Medium | Medium |
| **3 - Likely** | Low | Low | Medium | Medium | Medium |
| **4 - Very Likely** | Low | Medium | Medium | Medium | High |
| **5 - Highly Likely** | Low | Medium | Medium | High | High |

#### 3.5. Risk Register

The Risk Register documents all identified risks and contains:

**Essential Fields:**
*   **Risk Statement:** Clear description of the risk.
*   **Risk ID:** Unique identifier.
*   **Asset:** System, data, or resource affected.
*   **Risk Rating:** Low/Medium/High.
*   **Risk Treatment:** Mitigate/Accept/Transfer/Avoid.
*   **Mitigation/Transfer Plan:** Concrete actions to implement.
*   **Risk Impact:** Expected consequences.
*   **Risk Cause:** Origin or vulnerability exploited.
*   **Cost of Mitigation:** Investment required.
*   **Acceptance/Approval:** Approval by the risk owner.

**Example Register:**
*   **Risk Statement:** Sensitive data can be compromised through phishing attacks.
*   **Risk ID:** 4.
*   **Asset:** Confidential data (e.g., passwords).
*   **Risk Rating:** High.
*   **Risk Treatment:** The risk must be mitigated.
*   **Mitigation Plan:** Formal training and use of phishing detection software.

#### 3.6. Risk Treatment

There are four main treatment options:

1.  **Mitigate**
    *   Implement controls to reduce the likelihood or impact.
    *   *Example:* Install firewalls, implement MFA, encrypt data.
    *   It is the most common approach.
2.  **Accept**
    *   Acknowledge the risk and decide not to take action.
    *   Used when the cost of mitigation is greater than the potential impact.
    *   Requires formal approval from the risk owner.
3.  **Transfer**
    *   Pass the risk to third parties.
    *   *Example:* Cybersecurity insurance, outsourcing.
    *   The risk does not disappear, but financial responsibility is shared.
4.  **Avoid**
    *   Completely eliminate the activity that generates the risk.
    *   *Example:* Disable a vulnerable service, do not process sensitive data.
    *   Not always viable due to business requirements.

### 4. Risk Management Frameworks

#### 4.1. ISO 27005
*   International standard for information security risk management.
*   Provides guidelines for risk assessment and treatment.
*   Aligned with ISO 27001.

#### 4.2. NIST Risk Management Framework (RMF)
*   Framework developed by the National Institute of Standards and Technology (USA).
*   7-step iterative process.
*   Widely used in government and critical sectors.

#### 4.3. OCTAVE
*   Operationally Critical Threat, Asset, and Vulnerability Evaluation.
*   Focused on organizational risk assessment.
*   Collaborative approach involving different stakeholders.

---

## PART 2: THREAT DETECTION

### 5. Introduction to Threat Detection

Threat Detection is a critical process in cybersecurity that involves identifying, monitoring, and responding to malicious or suspicious activities in computer systems and networks.

#### 5.1. Objectives of Threat Detection
*   Identify attacks in real-time or near-real-time.
*   Correlate security events from multiple sources.
*   Reduce incident response time (MTTD and MTTR).
*   Minimize the impact of security compromises.
*   Comply with compliance and audit requirements.

### 6. Wazuh - SIEM/HIDS Platform

Wazuh is an open-source platform for threat detection, security analysis, and incident response. It functions as a SIEM (Security Information and Event Management) and HIDS (Host-based Intrusion Detection System).

#### 6.1. Wazuh Architecture

**Components:**
*   **Wazuh Manager:** Central server that receives, processes, and correlates events.
*   **Wazuh Agents:** Agents installed on endpoints that monitor locally.
*   **Dashboard/Interface:** Web interface (Kibana/OpenSearch) for visualization and management.

#### 6.2. Main Capabilities
*   Real-time log monitoring.
*   File Integrity Monitoring (FIM).
*   Rootkit and malware detection.
*   Vulnerability analysis.
*   Automatic Active Response.
*   Event correlation and alerts.
*   Regulatory compliance (PCI DSS, GDPR, HIPAA, ISO 27001).

### 7. File Integrity Monitoring (FIM)

File Integrity Monitoring is a security mechanism that monitors changes in critical files and directories of a system, allowing the detection of unauthorized modifications, suspicious behavior, or signs of compromise.

#### 7.1. How FIM Works

FIM operates by creating a baseline of the initial state of monitored files:
*   Permissions and owner.
*   File size.
*   Modification date.
*   Cryptographic hashes (SHA-1, SHA-256).

Whenever a change occurs, the Wazuh agent detects the event, compares it with the baseline, and generates a detailed alert.

#### 7.2. Types of Monitoring
*   **Periodic Checks:** File analysis at defined intervals.
*   **Real-time Monitoring:** Using inotify (Linux) or audit APIs (Windows).

### 7.3. FIM Configuration in Wazuh

**Linux Example (`/var/ossec/etc/ossec.conf`):**
```xml
<syscheck>
  <directories check_all="yes" realtime="yes"></directories>
  <directories check_all="yes" realtime="yes">/home/aluno</directories>
</syscheck>
```

**Windows Example:**
```xml
<syscheck>
  <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
  <directories check_all="yes" realtime="yes">C:\Users</directories>
</syscheck>
```

After making changes, always restart the agent.

### 7.4. FIM Use Cases
*   Detection of privilege escalation.
*   Identification of malware persistence.
*   Monitoring of critical configuration files.
*   Detection of backdoor installation.
*   Changes in system binaries.
*   Compliance (PCI DSS, ISO 27001, NIST).

### 8. Detection of Specific Attacks

#### 8.1. Brute Force Attack

Brute force attacks attempt to guess credentials through multiple authentication attempts. Wazuh detects and correlates failed attempts, generating security alerts.

**Related Wazuh Rules:**
*   5710 - Invalid user.
*   5711 - Failed attempt.
*   5716 - SSH brute force.
*   5720 - Multiple failures.
*   5503/5504 - PAM authentication.

**Indicators of Automated Attack:**
*   Multiple attempts in a short time.
*   Sequential patterns of users/passwords.
*   Single origin with multiple targets.

**Simulation with Hydra:**
```bash
# Installation
sudo apt install -y hydra

# Create password list
nano passwords.txt

# Run attack
sudo hydra -l badguy -P passwords.txt <TARGET_IP> ssh
```

**Questions for Reflection:**
1.  What is the difference between an isolated failed attempt and a brute force attack?
2.  Why is it important to correlate multiple events?
3.  What indicators clearly show an automated attack?
4.  What risks exist if these attempts are not mitigated?

**Exercises:**
*   Perform an attack against RDP on a Windows machine.
*   Create a custom rule to elevate severity.
*   Integrate with Active Response to block IP.
*   Map to MITRE ATT&CK (T1110 - Brute Force).

#### 8.2. SQL Injection

SQL Injection is an attack where malicious SQL code is inserted into input fields to manipulate databases. Wazuh detects common patterns in web server logs.

**Detected Patterns:**
*   SELECT, UNION, DROP, INSERT.
*   Strings with `' OR '1'='1`.
*   SQL Comments (`--`, `/* */`).
*   Query concatenation.

**Configuration for Apache Monitoring:**
```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>
```

**Attack Simulation:**
```bash
curl -XGET "http://<VICTIM_IP>/users/?id=SELECT+*+FROM+users"
```

**Detection Rule:**
*   31106 - SQL Injection attempt detected.

**Active Response:**
*(Note: Original document contained corrupted table data here, typically maps to blocking the IP or alerting)*

### 9. Threat Hunting and Active Response

#### 9.1. Threat Hunting

Threat Hunting is the proactive search for threats that may have evaded automatic defenses. It involves log analysis, event correlation, and investigation of anomalous behaviors.

#### 9.2. Active Response

Active Response allows automatic actions in response to security events, such as blocking IPs, isolating endpoints, or executing scripts.

**Example: Blocking Malicious IP**
*   IP Reputation (blacklists/whitelists).
*   Indicators of Compromise (IoCs).
*   Privileged user lists.
*   Malicious URLs.

**Advantages:**
*   Very fast.
*   Low performance impact.
*   Ideal for SOC and SIEM environments.
*   Scalable.

**Implementation Example:**
1.  Download malicious IP list:
    ```bash
    sudo wget https://iplists.firehol.org/files/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset
    ```
2.  Add attacker IP:
    ```bash
    sudo echo "<ATTACKER_IP>" >> /var/ossec/etc/lists/alienvault_reputation.ipset
    ```
3.  Convert to CDB format:
    ```bash
    sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py
    sudo /var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/os
    ```

### 10. Integration with IDS (Suricata)

#### 10.1. What is an IDS
An IDS (Intrusion Detection System) is a security system that monitors, analyzes, and detects malicious or suspicious activities on a network or system.

**Difference between IDS vs IPS:**
*   **IDS:** Detects and alerts (passive).
*   **IPS:** Detects and blocks (active).

#### 10.2. Types of IDS
*   **NIDS (Network-based IDS):** Monitors network traffic (e.g., Suricata, Snort).
*   **HIDS (Host-based IDS):** Monitors specific systems (e.g., Wazuh).

#### 10.3. Detection Methods
*   **Signature-based:** Compares with known attack patterns.
*   **Anomaly-based:** Detects deviations from normal behavior.

#### 10.4. Wazuh + Suricata Integration
Suricata (NIDS) can be integrated with Wazuh to correlate network events with host events, providing complete visibility.

**Detectable Attacks:**
*   Port scans and reconnaissance (nmap).
*   DoS/DDoS attacks.
*   Vulnerability exploits.
*   C2 (Command and Control) communications.

**Simulation:**
1.  **Ping Test:**
    ```bash
    ping -c 20 "<UBUNTU_IP>"
    ```
2.  **Nmap Scan:**
    ```bash
    nmap -sS --script=vuln <IP_UBUNTU>
    ```
3.  **DoS with GoldenEye:**
    ```bash
    git clone https://github.com/jseidl/GoldenEye.git
    cd GoldenEye
    ./goldeneye.py http://<UBUNTU_IP>
    ```

**Challenge:** Create an active response to block NMAP reconnaissance.

### 11. Integration with YARA

#### 11.1. What is YARA
YARA is a tool for detecting and classifying malware based on pattern identification in files or memory. It works as a rule engine.

**Use Cases:**
*   Detect known malware.
*   Classify malware families.
*   Identify suspicious files.
*   Support forensic analysis.
*   Integration with EDR, SIEM, and SOC.
*   Automate signature-based detections.

#### 11.2. How YARA Rules Work
A YARA rule describes patterns:
*   Text strings.
*   Binary strings (hexadecimal).
*   Regular expressions.
*   Logical combinations (AND, OR, NOT).
*   Conditions based on file size/type.

#### 11.3. Detection Process
1.  YARA receives a file or directory.
2.  Applies all configured rules.
3.  Evaluates the conditions.
4.  If it matches → positive match.
5.  Returns the rule name as the result.

#### 11.4. Integration with Wazuh

**Installation on the Agent:**
```bash
sudo apt update
sudo apt install -y make gcc autoconf libtool libssl-dev pkg-config jq
sudo curl -LO https://github.com/VirusTotal/yara/archive/v4.5.5.tar.gz
sudo tar -xvzf v4.5.5.tar.gz -C /usr/local/bin/ && rm -f v4.5.5.tar.gz
cd /usr/local/bin/yara-4.5.5/
sudo ./bootstrap.sh && sudo ./configure && sudo make && sudo make install && sudo make check
```

**Downloading Rules:**
```bash
sudo mkdir -p /tmp/yara/rules
sudo curl 'https://valhalla.nextron-systems.com/api/v1/get' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Referer: https://valhalla.nextron-systems.com/' -H 'Content-Type: application/x-www-form-urlencoded' --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111&format=text' -o /tmp/yara/rules/yara_rules.yar
```

**FIM Configuration to monitor directory:**
```xml
<directories check_all="yes" realtime="yes">/tmp/yara/malware</directories>
```

**Rules on the Server:**
```xml
<group name="syscheck,">
  <rule id="100300" level="7">
    <if_sid>550</if_sid>
    <field name="file">/tmp/yara/malware</field>
    <description>File modified in /tmp/yara/malware directory.</description>
  </rule>
  <rule id="100301" level="7">
    <if_sid>554</if_sid>
    <field name="file">/tmp/yara/malware</field>
    <description>File added to /tmp/yara/malware directory.</description>
  </rule>
</group>

<group name="yara,">
  <rule id="108000" level="0">
    <decoded_as>yara_decoder</decoded_as>
    <description>YARA grouping rule</description>
  </rule>
  <rule id="108001" level="12">
    <if_sid>108000</if_sid>
    <match>wazuh-yara: INFO - Scan result: </match>
    <description>File "$(yara_scanned_file)" matches positively. YARA Rule: $(yara_rule)</description>
  </rule>
</group>
```

**Challenge:** After malware detection, how to quarantine the files?

### 12. Web Application Firewall (WAF)

#### 12.1. What is a WAF
A WAF is a specialized security system that protects web applications against attacks at the HTTP/HTTPS layer (Layer 7). While traditional firewalls protect IPs and ports, a WAF protects application content and behavior.

**What the WAF Protects:**
*   URL parameters.
*   HTTP headers.
*   POST/PUT request body.
*   Input patterns.
*   Sessions and authentication.
*   APIs and JSON/XML.
*   Encrypted HTTPS traffic.

#### 12.2. OWASP Top 10
The WAF is the primary defense against OWASP Top 10 attacks:
*   SQL Injection.
*   Cross-Site Scripting (XSS).
*   Cross-Site Request Forgery (CSRF).
*   Command Injection.
*   Path Traversal.
*   Insecure Deserialization.
*   Security Misconfiguration.

#### 12.3. ModSecurity
ModSecurity is an open-source WAF that can be integrated with Apache, Nginx, or IIS. It uses the OWASP Core Rule Set (CRS).

**Installation:**
```bash
sudo apt install libapache2-mod-security2 -y
sudo a2enmod security2
sudo systemctl restart apache2
```

**Configuration:**
```bash
cd /etc/modsecurity/
sudo mv modsecurity.conf-recommended modsecurity.conf
sudo vi /etc/modsecurity/modsecurity.conf
```
Change `SecRuleEngine DetectionOnly` to `SecRuleEngine On`.

**Install OWASP CRS:**
```bash
cd ~
sudo wget https://github.com/coreruleset/coreruleset/archive/v3.3.0.tar.gz
sudo tar -xvzf v3.3.0.tar.gz
sudo mkdir /etc/apache2/modsecurity-crs
sudo mv coreruleset-3.3.0/ /etc/apache2/modsecurity-crs
cd /etc/apache2/modsecurity-crs/coreruleset-3.3.0
sudo mv crs-setup.conf.example crs-setup.conf
```

**Integrate into Apache:**
```bash
sudo vi /etc/apache2/mods-available/security2.conf
```
Add:
```apache
Include /etc/apache2/modsecurity-crs/coreruleset-3.3.0/crs-setup.conf
Include /etc/apache2/modsecurity/coreruleset-3.3.0/rules/*.conf
```

**SQL Injection Test:**
`http://IP_DO_SERVIDOR/?id=1' OR '1'='1`

**Operation Modes:**
*   **DetectionOnly:** Logs but does not block.
*   **On:** Blocks malicious requests (403 Forbidden).

### 13. Cybersecurity Architectures

#### 13.1. Defense in Depth

Defense in Depth is a strategy based on multiple layers of protection. The goal is to maintain security even when one layer fails.

**Importance:**
*   No single control is perfect in isolation.
*   Layers increase resilience and mitigate failures.
*   It makes attacks harder and reduces impact.
*   It serves as the basis for Zero Trust, SASE, and SOC.

**Layers of Defense in Depth:**

| Layer | Components |
| :--- | :--- |
| **Perimeter** | Firewalls, NGFW, IDS/IPS, VPN, Traffic Filtering |
| **Internal Network** | Segmentation, VLANs, NAC, Microsegmentation, Zero Trust |
| **Endpoints** | EDR, Antivirus, Hardening, Patch Management, Device Control |
| **Applications** | WAF, MFA, Input Validation, OWASP Top 10, Secure Coding |
| **Data** | Encryption (transit and rest), DLP, Classification, Backup |
| **People** | Training, Phishing Simulations, Policies, Awareness |

#### 13.2. Zero Trust Architecture (ZTA)

Zero Trust is a security model that assumes no entity is trusted by default, whether inside or outside the network.

**Fundamental Principles:**
1.  **Never Trust, Always Verify:** Eliminates implicit trust in internal networks.
2.  **Least Privilege:** Access only to what is strictly necessary.
3.  **Assume Breach:** Act as if there is already a compromise.
4.  **Continuous Verification:** Continuous verification of identity, device, and context.
5.  **Deny by Default:** Blocks everything that is not explicitly allowed.

**ZTA Components:**
*   **Identity:** MFA, SSO, Identity Management (Entra ID, Okta).
*   **Devices:** MDM, EDR, Posture Assessment.
*   **Network:** ZTNA, Microsegmentation, Software-Defined Perimeter.
*   **Applications:** mTLS, API Gateway, WAF, OAuth2/OIDC.
*   **Data:** Encryption, DLP, Classification.
*   **Visibility:** SIEM, UEBA, XDR, Threat Intelligence.

**Microsegmentation:**
*   Creates "islands" and "pockets" of communication.
*   Each workload only communicates with necessary resources.
*   Limits lateral movement of attackers.
*   Traditional problem: Flat networks allow unlimited movement.

**VPN vs ZTNA:**
*   **VPN:** Access to the entire network.
*   **ZTNA:** Access only to the specific application.
*   ZTNA is the modern replacement for VPN.

**Defense against Identity Attacks:**
*   Password spraying.
*   Token theft.
*   OAuth consent phishing.

### 14. SOC and SIEM

#### 14.1. Security Operations Center (SOC)

The SOC is a monitoring and incident response center that operates 24/7.

**SOC Components:**
*   **SIEM:** Centralizes logs and correlates events.
*   **SOAR:** Automation and orchestration of response.
*   **Threat Intelligence:** Threat feeds and IoCs.
*   **Playbooks:** Response procedures.
*   **Analysts:** Tier 1, 2, and 3 (monitor and respond 24/7).

#### 14.2. SIEM (Security Information and Event Management)

SIEM is a solution that centralizes logs from multiple sources, correlates events, and generates security alerts.

**SIEM Functions:**
*   Log collection from all sources.
*   Event normalization and parsing.
*   Event correlation.
*   Alert generation.
*   Dashboards and visualizations.
*   Reporting and compliance.

**SIEM Tools:**
*   Splunk.
*   Microsoft Sentinel.
*   Elastic (ELK Stack).

**Zero Trust + SIEM:**
*   Total logging: AD, endpoints, cloud, API, firewall, WAF, VPN/ZTNA.
*   Dynamic risk score.
*   Predictive alerts (machine learning).
*   Behavioral detection (UEBA).
*   XDR (correlated endpoint + network + cloud detection).

### 15. Important Concepts for the Test

#### 15.1. Wazuh Rules

Wazuh rules are composed of:
*   **rule id:** Unique identifier.
*   **level:** Severity (0-15).
*   **if_sid:** Parent rule (inheritance).
*   **match/regex:** Pattern to detect.
*   **description:** Alert description.
*   **field:** Specific field to check.
*   **list:** Reference to CDB list.

#### 15.2. Severity Levels

| Level | Meaning |
| :--- | :--- |
| 0 | Ignored |
| 1-3 | Informational |
| 4-7 | Low / Medium |
| 8-10 | High |
| 11-15 | Critical |

#### 15.3. MITRE ATT&CK

MITRE ATT&CK is a framework that categorizes tactics, techniques, and procedures (TTPs) used by attackers.

**Mapping Examples:**
*   T1110 - Brute Force.
*   T1190 - Exploit Public-Facing Application.
*   T1059 - Command and Scripting Interpreter.
*   T1071 - Application Layer Protocol (C2).
*   T1027 - Obfuscated Files or Information.

#### 15.4. Important Differences

**IDS vs IPS:**
*   **IDS:** Detects (passive).
*   **IPS:** Blocks (active).

**NIDS vs HIDS:**
*   **NIDS:** Network-based (Suricata).
*   **HIDS:** Host-based (Wazuh).

**SIEM vs SOAR:**
*   **SIEM:** Correlation and analysis.
*   **SOAR:** Automation and orchestration.

**WAF vs Firewall:**
*   **Firewall:** Layer 3/4 (IP/Port).
*   **WAF:** Layer 7 (HTTP/Application).

### 16. Best Practices in Threat Detection

*   **Continuous Monitoring:** 24/7 of all critical assets.
*   **Event Correlation:** Do not trust isolated alerts.
*   **Rule Tuning:** Adjust rules to reduce false positives.
*   **Automation:** Use Active Response for rapid response.
*   **Threat Intelligence:** Integrate IoC feeds.
*   **Centralized Logging:** All logs in a SIEM.
*   **Retention:** Keep logs for at least 90 days (common requirement).
*   **Playbooks:** Have documented procedures.
*   **Testing:** Simulate attacks regularly (Red Team/Purple Team).
*   **Training:** Continuously train analysts.
*   **Defense in Depth:** Multiple layers of protection.
*   **Least Privilege:** Minimum necessary access.
*   **Patch Management:** Keep systems updated.
*   **Backup:** Regular and tested backups.

---

### 17. Executive Summary for the Test

#### 17.1. Risk Management

**Key Concepts:**
*   Risk = Vulnerability × Threat × Impact.
*   Likelihood: 1-5 (Very Unlikely to Highly Likely).
*   Impact: 1-5 (Insignificant to Catastrophic).
*   Matrix: Low (1-7), Medium (7-17), High (17-25).
*   Treatment: Mitigate, Accept, Transfer, Avoid.

**Roles:**
*   Risk Manager (leadership).
*   Risk Owner (decision).
*   Specialist (expertise).
*   Subject Matter Experts (technical).

**Threats:**
*   Black Hats.
*   Employees.
*   Insider Threats.

#### 17.2. Main Tools
*   **Wazuh:** SIEM/HIDS for detection and response.
*   **Suricata:** NIDS for network monitoring.
*   **YARA:** Rule-based malware detection.

#### 17.3. Attacks to Know
*   **Brute Force:** SSH, RDP (Rules 5710, 5711, 5716, 5720).
*   **SQL Injection:** Rule 31106.
*   **Port Scanning:** nmap.
*   **DoS/DDoS:** GoldenEye.
*   **Malware:** YARA detection.

#### 17.4. Architectures
*   **Defense in Depth:** Multiple layers (Perimeter, Network, Endpoints, Applications, Data, People).
*   **Zero Trust:** Never trust, always verify; Least privilege; Assume breach.
*   **SOC:** 24/7 monitoring with SIEM, SOAR, Threat Intelligence.

#### 17.5. Technical Concepts
*   **FIM:** File Integrity Monitoring - baseline + alerts.
*   **Active Response:** Automatic response to events.
*   **CDB Lists:** Fast correlation (IPs, IoCs).
*   **SIEM:** Centralization + log correlation.
*   **IDS vs IPS:** Detection vs Prevention.
*   **NIDS vs HIDS:** Network vs Host.
*   **Microsegmentation:** Limit lateral movement.
*   **ZTNA:** Modern replacement for VPN.

### Conclusion

This complete guide compiled ALL class material on Threat Detection and Risk Management in Cybersecurity. Studying and understanding these concepts, tools, and architectures is fundamental to effectively detecting, responding to, and mitigating threats.

### Final Checklist for the Test:
- [x] Understand risk concepts (definition, components, scales).
- [x] Know types of threats and actors.
- [x] Master roles in risk management.
- [x] Know how to use a risk matrix and risk register.
- [x] Understand risk treatment options.
- [x] Know how to configure FIM and Active Response.
- [x] Identify and detect common attacks (Brute Force, SQL Injection).
- [x] Understand differences between IDS/IPS, NIDS/HIDS.
- [x] Know Wazuh + Suricata + YARA integration.
- [x] Know what a WAF and ModSecurity are.
- [x] Understand Defense in Depth (layers).
- [x] Master Zero Trust principles.
- [x] Understand SOC and SIEM.
- [x] Know Wazuh rules and severity levels.
- [x] Know how to map attacks to MITRE ATT&CK.

*Document automatically generated from all class material on Threat Detection in Cybersecurity.*
