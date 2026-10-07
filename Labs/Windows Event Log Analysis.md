# SOC Incident Analysis: Rogue Admin Account via Service Account RDP

**Lab:** Windows Event Log Analysis from codelivly

**Situation:** Overnight something happened on the finance file server `FIN-FS-02` that alerted nothing loudly, and there is **no alert feed** for this investigation. The only source is the raw Windows Security log.

**Evidence** (all derivable from these four files using time-based filtering and session correlation):

| File | Content |
|---|---|
| `security-events.json` | Raw Security log, about 350 events (349 counted), one JSON object per line, filterable with `jq` |
| `security-events.txt` | The same events rendered in Event Viewer format |
| `logon-types.md` | Reference mapping Logon Types and event IDs |
| `asset-inventory.csv` | Host ownership, service account register, and change control |


## 1. Executive Summary

At **02:14:33 UTC** on 2026-04-22 the service account `svc_backup` opened an **RDP session (Logon Type 10)** to `FIN-FS-02` from `10.10.9.77` (WKS-2291, a Marketing workstation). Per the asset inventory this account only runs as a **service (Type 5)**, and interactive logon is **not an approved use**. Within five minutes, the same session created a new local account, `helpdesk_svc`, and added it to the local **Administrators** group. No change ticket exists for that date.

This is a compromised service account used for lateral movement, followed by persistence and privilege escalation.

Alongside with recomendations, I addressed **Sigma rule** for forder detections to mitigate the previous lack of visivility. (added 7 out 2026)

---

## 2. Investigation Steps


### 1 - Read the asset inventory

```bash
cat /var/log/soc/asset-inventory.csv
```

**Finding:**
- `svc_backup` runs the nightly backup on FIN-FS-02 **as a service (Type 5)**. Interactive logon is **not approved**.
- `10.10.9.77` = **WKS-2291**, owner `tadeyemi`, **Marketing** (standard staff workstation, not an IT or admin host).
- **No change ticket** was raised for 2026-04-22.


### 2 Discover the JSON field structure

The first attempts (`.EventLogon.Type`, `.LogonType`) returned `null` because the fields are nested. Listing all paths revealed the correct location:

```bash
jq -r '[paths(scalars) | map(tostring) | join(".")] | unique[]' security-events.json | head -60
```

**Finding:** The logon type is at **`.EventData.LogonType`**, the account at `.EventData.TargetUserName`, the source IP at `.EventData.IpAddress`, and the session ID at `.EventData.TargetLogonId`.


### 3 - Count logon types across all successful logons

```bash
jq -r 'select(.EventID==4624) | .EventData.LogonType' security-events.json | sort | uniq -c
```

<img width="846" height="60" alt="image" src="https://github.com/user-attachments/assets/03b7aca5-27e9-42a1-9190-6ea79f133546" />


**Finding:** 163 successful logons. Type 3 (network) is normal for a file server. Only **7 are Type 10 (RDP)**, which is the small set worth examining.


### 4 - Compare each account against its own normal behaviour

```bash
jq -r 'select(.EventID==4624) | [.EventData.TargetUserName, .EventData.LogonType] | @tsv' security-events.json \
  | sort | uniq -c | sort -rn
```

<img width="1002" height="302" alt="image" src="https://github.com/user-attachments/assets/c426cb2f-1750-4482-af1a-93c22968e4a9" />


**Finding:** `svc_backup` has **6 normal Type 5 logons** and **1 Type 10 logon**. That single RDP session breaks the account's baseline. The other Type 10 logons belong to the IT admin accounts, where RDP is expected.



### 5 - List every RDP (Type 10) logon

```bash
jq -r 'select(.EventID==4624 and (.EventData.LogonType|tostring)=="10")
  | [.TimeCreated, .Computer, .EventData.TargetUserName, .EventData.IpAddress, .EventData.WorkstationName, .EventData.TargetLogonId] | @tsv' security-events.json
```

<img width="1162" height="138" alt="image" src="https://github.com/user-attachments/assets/b727fd7b-858d-4834-b8ad-5ef693eb67f0" />


**Finding:** The suspicious session is the first row: wrong account type, wrong hour (02:14), and wrong source (Marketing subnet `10.10.9.x`, not the IT subnet `10.10.4.x`).


### 6 - Inventory of all event types in the log

```bash
jq -r '.EventID' security-events.json | sort | uniq -c
```

<img width="581" height="114" alt="image" src="https://github.com/user-attachments/assets/9cb9d968-507d-44dc-994f-204cb927e8fa" />

**Finding:** There is exactly **one** account creation (4720) and **one** local group change (4732) in the whole log, so those two events are the whole story of what was changed.


### 7 - Inspect the account creation and group change

```bash
jq 'select(.EventID|IN(4720,4732))' security-events.json
```

<img width="486" height="632" alt="image" src="https://github.com/user-attachments/assets/2469ff16-816a-47e9-812b-c9e91a9a14f3" />

**Finding:** Both actions carry `SubjectLogonId = 0x3E7A91C`, which ties them to the suspicious RDP session.

### 8 - Rule out brute force by reviewing the failed logons (Event 4625)

```bash
jq 'select(.EventID == 4625)' security-events.json
```

**Output summary (14 events, all on 2026-04-22):**

| Account | Failures | Times (UTC) | Source IPs |
|---|---|---|---|
| lnguyen | 4 | 08:09, 15:09, 16:28, 16:38 | 10.10.9.198, .122, .195, .66 |
| adesina | 2 | 10:45, 13:21 | 10.10.9.100, .154 |
| tbalogun | 2 | 13:56, 14:34 | 10.10.9.49, .75 |
| mokafor | 2 | 14:22, 14:51 | 10.10.9.26, .75 |
| fokonkwo | 1 | 08:43 | 10.10.9.42 |
| tadeyemi | 1 | 09:03 | 10.10.9.181 |
| dkumar | 1 | 10:06 | 10.10.9.194 |
| bchukwu | 1 | 14:02 | 10.10.9.153 |

**Common fields:** every event is Logon Type 3, `NtLmSsp` / `NTLM`, `Status 0xC000006D` (logon failure) with `SubStatus 0xC000006A` (**wrong password for a valid user**).

**Finding:** these look like ordinary background noise (mistyped passwords by regular staff), **not** an attack:
- **None target `svc_backup`**, `helpdesk_svc` or either admin account.
- **None occur before the incident.** The earliest failure is at 08:09Z, almost 6 hours after the 02:14Z attacker logon, so there was no guessing activity leading up to it.
- No account has more than 4 failures, spread over most of the day with a different source host each time. That does not match brute force or password spraying, which would show many failures in a short window from one source.
- One minor oddity: `10.10.9.75` appears for two different users (tbalogun on WKS-1919 at 14:34 and mokafor on WKS-1363 at 14:51) with different workstation names. With only two events it is low confidence, but it is worth a look if the host is later investigated.

**Conclusion:** this log does not show how the `svc_backup` credentials were obtained. The initial credential compromise happened outside the evidence provided (the suspect pivot host WKS-2291 is the place to look).


## 4. Attack Timeline

Reconstructed by following Logon ID `0x3E7A91C`.

| Time (UTC) | Event ID | Action |
|---|---|---|
| 02:14:33 | 4624 (Type 10) | RDP logon as `svc_backup` from `10.10.9.77` (WKS-2291) |
| 02:14:33 | 4672 | Special privileges assigned (incl. `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`) |
| 02:19:07 | 4720 | Account `helpdesk_svc` created |
| 02:19:41 | 4732 | `helpdesk_svc` added to local **Administrators** group |

Logon to account creation took about 4.5 minutes, and creation to privilege escalation took 34 seconds.

---

## 5. Indicators of Compromise and Why This Is Malicious

| Indicator | Detail |
|---|---|
| Compromised account | `svc_backup` |
| Rogue account | `helpdesk_svc` (name chosen to look like a legitimate support account) |
| Rogue account SID | `S-1-5-21-1004336348-1177238915-682003330-2117` |
| Suspect source host | `WKS-2291` / `10.10.9.77` (owner `tadeyemi`, Marketing) |
| Target host | `FIN-FS-02` |
| Session Logon ID | `0x3E7A91C` |

**Why this is malicious and not a benign admin action:**

1. The account is registered as a **service only**, and interactive logon is explicitly not approved.
2. All of its 6 other logons were **Type 5**; this is its only Type 10.
3. The logon happened at **02:14 UTC**, while the real admin RDP sessions occurred between 09:03 and 16:26 UTC.
4. The source was a **Marketing workstation**, not an IT host.
5. The session performed **account creation and admin group changes**, which a backup service never does.
6. **No change ticket** exists for 2026-04-22.

> Note: an internal source IP proves nothing, since an attacker who already controls one workstation has an internal address by definition. The logon type and account behaviour are the reliable signals.

---

## 6. MITRE ATT&CK Analysis

| Tactic | Technique | ID | Evidence in this incident |
|---|---|---|---|
| Initial Access / Defense Evasion / Persistence / Privilege Escalation | Valid Accounts: Domain Accounts | **T1078.002** | Legitimate `svc_backup` credentials used (`SubjectDomainName: ABCFIN`). How they were obtained is **not visible** in this log. |
| Lateral Movement | Remote Services: Remote Desktop Protocol | **T1021.001** | 4624 Type 10 from WKS-2291 to FIN-FS-02. |
| **Persistence** | **Create Account: Local Account** | **T1136.001** | **Event 4720 created `helpdesk_svc`** (target domain = the host `FIN-FS-02`). This is the answer to Question 8. |
| Persistence / Privilege Escalation | Account Manipulation | **T1098** | Event 4732 added `helpdesk_svc` to local Administrators. |

### Attack chain

```
Compromised svc_backup credentials (T1078.002)
        |
        v
RDP from WKS-2291 (Marketing) to FIN-FS-02 (T1021.001)
        |
        v
Create local account helpdesk_svc (T1136.001)   <-- persistence
        |
        v
Add helpdesk_svc to Administrators (T1098)      <-- privilege escalation
```

### Analyst notes

- **Why T1136.001 and not T1136.002:** the new account's domain field is the server name `FIN-FS-02`, which indicates a **local** account on the file server. The member DN in Event 4732 (`CN=helpdesk_svc,CN=Users,DC=abcfin,DC=local`) is in a domain-style format, so confirm on the host that the account is local before closing the case. If it turns out to be a domain account, the technique becomes **T1136.002**.
- **Why this is persistence:** `helpdesk_svc` gives the attacker a second, admin-level way back in, so changing the `svc_backup` password alone would not remove their access.
- **Likely compromised host:** WKS-2291 is probably compromised and should be treated as the pivot point.

---

## 7. Recommended Actions

**Immediate containment**
- Disable and delete `helpdesk_svc`; remove it from `Administrators` on FIN-FS-02.
- Reset the `svc_backup` credentials and block interactive logon for the account (deny log on locally / through Remote Desktop Services).
- Isolate WKS-2291 and begin forensic triage (owner: `tadeyemi`).

**Follow-up investigation**
- Search all logs for any use of `helpdesk_svc` after 02:19:41Z.
- Retrieve the Event 4634 (logoff) for `0x3E7A91C` to get the session duration.
- Review what `svc_backup` can access and what was read or copied during the session (it holds `SeBackupPrivilege`).
- Review why `svc_backup` holds `SeTakeOwnershipPrivilege`, which the admin accounts do not have.

## 8. Lab Answers

| # | Question | Answer | Evidence |
|---|----------|--------|----------|
| 1 | Which Event ID records a SUCCESSFUL logon? | **4624** | `logon-types.md`, Step 1 |
| 2 | Which account performed the suspicious logon? | **`svc_backup`** | Step 5, Step 6 |
| 3 | What Logon Type was that logon? | **10** (RemoteInteractive / RDP) | Step 5 |
| 4 | What was the source IP address of that logon? | **`10.10.9.77`** (WKS-2291) | Step 6 |
| 5 | What is the Logon ID of that session? | **`0x3E7A91C`** | Step 6 |
| 6 | What NEW account was created during that session? | **`helpdesk_svc`** | Step 8 (Event 4720) |
| 7 | Which privileged group was the new account added to? | **Administrators** (local, FIN-FS-02) | Step 8 (Event 4732) |
| 8 | Which MITRE ATT&CK technique covers creating an account to keep access? | **T1136.001** (Create Account: Local Account; parent technique **T1136**) | Section 6 |


## 9. - Detection Engineering
### Build Sigma Rule

The investigation showed that no single event was enough to catch this attack. A successful RDP logon, an account creation and a group change are all routine on their own, and the source IP was an approved internal address. Only the sequence inside one logon session (same Logon ID) was malicious. The next phase was therefore to turn the manual analysis into detection logic.

- **Rule 1, suspicious RDP logon:** flags Type 10 logons from outside the approved IT range `10.10.4.0/24`. 
- **Building blocks:** account creation (4720) and group membership change (4732/4728/4756) are not alerted on their own because they would be too noisy. They are used only as inputs to the aggregate rule.
- **Aggregate rule (critical):** fires when a suspicious RDP logon is followed, in the same session and within 10 minutes, by an account creation and a group add. This maps to T1021.001, T1136.001 and T1098. The real attack took 308 seconds, so a 10 minute window catches it with margin, while a 5 minute window would have missed it.
- **Validation:** the logic was tested with `jq` and Python against the event log, and it matches the `svc_backup` session (`0x3E7A91C`) and none of the admin sessions.
- **Known limit:** an attacker pivoting from a host inside `10.10.4.0/24` with a non-service account would not start the chain. Need to address that :S

```yml
title: RDP Logon From Outside the IT Subnet
id: e92c0fc1-93ba-4a35-8077-89c82ce3d01f
status: experimental
description: Any account doing an RDP logon (Type 10) from a source outside the approved IT range 10.10.4.0/24.
tags:
    - attack.t1021.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    it_subnet:
        IpAddress|cidr: '10.10.4.0/24'
    condition: selection and not it_subnet
level: high
---
# Building blocks for the aggregate rule below. Too noisy to alert on alone.
title: Building Block - RDP Logon (T1021.001)
id: 9d0bcc6d-fcae-438e-9523-dc42876c8911
name: rdp_logon
status: experimental
description: Successful RDP logon (Type 10). Used only as input to the aggregate rule.
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    condition: selection
level: informational
---
title: Building Block - Account Created (T1136.001)
id: 856a9253-471f-4b5f-bf61-aaad1775c080
name: account_created
status: experimental
description: User account created (4720). Used only as input to the aggregate rule.
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    condition: selection
level: informational
---
title: Building Block - Member Added to Group (T1098)
id: 5c1f6a52-6f3a-4c0e-9b1a-3a8d7e2b4f10
name: group_member_added
status: experimental
description: Member added to a local, global or universal security group (4732, 4728, 4756). Used only as input to the aggregate rule.
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4732
            - 4728
            - 4756
    condition: selection
level: informational
---
title: RDP Logon, Account Creation and Group Add in One Session
id: 93bdd2ea-2c6e-405d-8d01-19911d57515a
name: rdp_create_account_group_add
status: experimental
description: |
    High value aggregate rule. In ONE logon session (same Logon ID), an RDP logon (T1021.001)
    is followed by an account creation (T1136.001) and then a group membership change (T1098).
    The name of the account and the source IP do not matter. Only the chain does.
    The Logon ID is TargetLogonId on the 4624 and SubjectLogonId on the 4720 and 4732,
    so the alias SessionId maps them together.
tags:
    - attack.lateral-movement
    - attack.t1021.001
    - attack.persistence
    - attack.t1136.001
    - attack.t1098
    - attack.privilege-escalation
correlation:
    type: temporal_ordered
    rules:
        - rdp_logon
        - account_created
        - group_member_added
    group-by:
        - Computer
        - SessionId
    aliases:
        SessionId:
            rdp_logon: TargetLogonId
            account_created: SubjectLogonId
            group_member_added: SubjectLogonId
    timespan: 30m
falsepositives:
    - An administrator who RDPs in, creates a user and adds it to a group in one sitting. Check the change ticket.
level: critical
```
