This lab at codelivly Soc Investigation - RDP Failed Login Analysis

# RDP Failed Login Analysis: Investigation Writeup

## Summary

Event ID 4625 failures show an external source, **203.0.113.88** (Sao Paulo, Brazil per the GeoIP table), running **username enumeration followed by password guessing**. The attack ended in a **successful logon to `eabiola`** at 09:31:15Z. That account had logged on from the Lagos head office 79 minutes earlier, which is **impossible travel**. Treat `eabiola` as compromised.

---

## Evidence reviewed

| File | Purpose |
|---|---|
| `security-events.json` | Windows events (4624/4625), queried with `jq` |
| `logon-failure-codes.md` | SubStatus code reference |
| `geoip-lookup.csv` | Offline IP-to-location enrichment |

---

## Methodology

Every query below is exactly as run, so it can be copied and re-run to reproduce the findings.

### 1. Split failures by SubStatus
The `FailureReason` text is identical for "user doesn't exist" and "wrong password", so `SubStatus` is the field that matters.

**Query:**
```bash
jq -r 'select(.EventID == 4625) | .EventData.SubStatus' /var/log/soc/security-events.json \
  | sort | uniq -c | sort -rn
```
<img width="1018" height="65" alt="image" src="https://github.com/user-attachments/assets/c3a4dd7e-bd4e-4598-a561-962be606d7ea" />


| SubStatus | Meaning | Count |
|---|---|---|
| `0xC000006A` | Wrong password (account exists) | 27 |
| `0xC0000064` | Username does not exist | 24 |
| `0xC0000234` | Account locked out | 3 |

### 2. Identify enumerated usernames

**Query:**
```bash
jq -r 'select(.EventID == 4625 and .EventData.SubStatus == "0xC0000064")
       | .EventData.TargetUserName' /var/log/soc/security-events.json | sort -u
```
<img width="702" height="208" alt="image" src="https://github.com/user-attachments/assets/aad4e156-3ce9-486b-b238-1d6eecd259f4" />



**12 non-existent names.** These are generic, commonly guessed names, which points to wordlist-driven enumeration.

### 3. Identify real accounts being guessed

**Query:**
```bash
jq -r 'select(.EventID == 4625 and .EventData.SubStatus == "0xC000006A") | .EventData.TargetUserName' /var/log/soc/security-events.json | sort | uniq -c | sort -rn
```

<img width="1121" height="185" alt="image" src="https://github.com/user-attachments/assets/0b718c25-e8ef-4bc4-8707-c6aa21c20b86" />


Nine real accounts had bad-password events.

### 4. Correlate by time and source IP
I pulled every 4624/4625 event for those nine accounts and sorted by user and time.

**Query:**
```bash
jq -r 'select((.EventID == 4624 or .EventID == 4625) and IN(.EventData.TargetUserName; "eabiola", "adesina", "rpatel", "kchen", "mokafor", "dkumar", "fokonkwo", "bchukwu", "auzoma")) | "\(.TimeCreated) | \(.EventData.TargetUserName) | \(.EventID) | \(.EventData.IpAddress)"' /var/log/soc/security-events.json \
  | sort -t'|' -k2,2 -k1,1
```
- **Noise:** single failures from internal `10.10.4.x` addresses, which are normal typos and followed by successful logons. This covers `mokafor`, `dkumar`, `fokonkwo`, `bchukwu`, `auzoma`, and one failure for `adesina`.
- **Attack:** bursts from **203.0.113.88** only, against `adesina`, `eabiola`, `kchen` and `rpatel`.

  Confirmed the sucessefull login at `eabiola` account compromised, by looking at diference at hours we can confirm a Impossible Travel scenario, where the geolocations login was 6000km appart, 79min appart it's impossible.

  <img width="555" height="125" alt="image" src="https://github.com/user-attachments/assets/cea2861a-62ce-426e-b809-94d76d18cce2" />


## Findings

### Finding 1: Enumeration, then password guessing
Per the code reference, a source that moves from `0xC0000064` to `0xC000006A` has learned which accounts exist. The attacker moved from generic names to guessing passwords against **real** staff accounts.

*Evidence: queries 1, 2 and 3.*

### Finding 2: Burst attack timeline (2026-07-08, UTC)

| Time | Target | Failures from 203.0.113.88 |
|---|---|---|
| 02:48:11 to 02:49:36 | `adesina` | 4 |
| 02:50:00 to 02:51:35 | `eabiola` | 4 |
| 02:52:03 to 02:53:33 | `kchen` | 4 |
| 02:54:10 to 02:56:53 | `rpatel` | 7 (4 bad password, then lockout; see note) |

The attacker guessed 4 times per account, then moved to the next one. That is a low-and-slow pattern designed to stay under lockout thresholds. `rpatel` shows 7 failures but only 4 are `0xC000006A`. The remaining 3 are consistent with the 3 `0xC0000234` lockout events. This is inferred and **not yet confirmed** (see "Gaps").

*Evidence: query 4.*

### Finding 3: Successful compromise of `eabiola`
After the overnight burst, the attacker returned about 6.5 hours later and targeted only `eabiola`:

| Time (UTC) | Event | Source |
|---|---|---|
| 08:12:15 | 4624 success | 10.10.4.37 (Lagos HQ) |
| 09:28:58 | 4625 fail | 203.0.113.88 |
| 09:30:01 | 4625 fail | 203.0.113.88 |
| **09:31:15** | **4624 success** | **203.0.113.88 (Sao Paulo)** |

*Evidence: queries 4 and 5.*

### Finding 4: Impossible travel

- Lagos to Sao Paulo is about 6,000 km (`geoip-lookup.csv`).
- The gap between the two logons is 79 minutes.
- That would require about **4,550 km/h**, versus about 900 km/h for commercial aircraft. Flight time alone would be roughly 6.7 hours.

**False-positive check** (VPN, CGNAT, cloud sync):
- The corporate VPN pool is `10.20.7.0/24` and exits in Lagos, so it cannot explain a Brazil address.
- 203.0.113.0/24 is a hosting provider with no tie to the organisation.
- The same IP had already attacked this account and three others that night.

Together these corroborate a real compromise, not an artefact.

### Finding 5: Scope
In the events reviewed, `adesina`, `kchen` and `rpatel` had no successful logon from the attacker IP. Only `eabiola` was breached.

## Answers to the lab questions

| # | Question | Answer | Justification |
|---|---|---|---|
| 1 | SubStatus code for "user name does not exist" | `0xC0000064` | Defined in `logon-failure-codes.md`. `0xC000006A` is a wrong password on an existing account, but the `FailureReason` text is identical, so only `SubStatus` tells them apart. |
| 2 | Distinct non-existent usernames tried | **12** | 24 events with `0xC0000064`, but `sort -u` collapses them to 12 names: `admin, administrator, backup, guest, helpdesk, operator, rdpuser, scanner, sql, temp, test, user1`. |
| 3 | Account compromised | `eabiola` | Only account with a successful 4624 from the attacker IP, right after two failed attempts. |
| 4 | Source IP of the malicious logon | `203.0.113.88` | Source of the 4624 for `eabiola`. The same IP also produced the overnight failures against `adesina`, `eabiola`, `kchen` and `rpatel`. |
| 5 | Country of that IP | Brazil (Sao Paulo) | `203.0.113.0/24` in `geoip-lookup.csv`, listed as a hosting provider. |
| 6 | Time of the malicious logon | `2026-07-08 09:31:15` | The 4624 event for `eabiola` from `203.0.113.88` (UTC). |
| 7 | Minutes between the two successful logons | **79** | 08:12:15Z (from `10.10.4.37`, Lagos HQ) to 09:31:15Z (from Sao Paulo) is 1h 19m. Lagos to Sao Paulo is about 6,000 km, which would need about 4,550 km/h. |
| 8 | MITRE technique: abusing an internet-facing remote access service | `T1133` | External Remote Services. RDP exposed to the internet was the entry point. |

---

## MITRE ATT&CK analysis
### Detection and mitigation mapping

| Control | ATT&CK reference | Applies to |
|---|---|---|
| Alert on `0xC0000064` followed by `0xC000006A` from one source | Data source: User Account Authentication (DS0002) | T1087, T1110 |
| Impossible-travel alert using GeoIP enrichment | Data source: Logon Session (DS0028) | T1078 |
| Enforce MFA on RDP and VPN | M1032 Multi-factor Authentication | T1110, T1133, T1078 |
| Account lockout and password policy | M1036 Account Use Policies, M1027 Password Policies | T1110 |
| Do not expose RDP to the internet, require VPN or gateway | M1035 Limit Access to Resource Over Network | T1133 |
| Block `203.0.113.88` and hosting-provider ranges where possible | M1037 Filter Network Traffic | T1133 |

---

## Conclusion

| Item | Result |
|---|---|
| Attack type | Username enumeration, then password guessing |
| Attacker source | 203.0.113.88 (Sao Paulo, hosting provider) |
| Accounts targeted | `adesina`, `eabiola`, `kchen`, `rpatel` |
| Compromised account | **`eabiola`**, 09:31:15Z |
| Detection method | SubStatus analysis plus impossible travel |

## Recommended actions

1. Disable `eabiola` and force a password reset and session revocation.
2. Block 203.0.113.88 at the perimeter and review other exposed RDP hosts.
3. Check what `eabiola` did after 09:31:15Z, including lateral movement and the logon type.
4. Reset passwords for `adesina`, `kchen` and `rpatel` as a precaution, since their passwords were guessed at.
5. Put RDP behind a VPN or MFA, and add an alert for `0xC0000064` followed by `0xC000006A` from one source.



