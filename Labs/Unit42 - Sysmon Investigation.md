# HTB Sherlock: Unit42

| | |
|---|---|
| **Platform** | Hack The Box (Sherlocks) |
| **Category** | DFIR / Sysmon log analysis |
| **Artifact** | `unit42.zip` (SHA1: `1D8AC45395551187EAF23793CE525056C4136D6E`) |
| **Tooling** | Sysmon logs (EVTX), event search/query |

## Scenario

Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the **initial access** stage of the campaign. In this Sherlock you familiarize yourself with Sysmon logs and various useful Event IDs for identifying and analyzing malicious activities on a Windows system. The base for this investigation is the use of **Sysmon** and correlate with **Mitre Attack Framework**.

## Sysmon Event IDs used

| Event ID | Name | Used for |
|---|---|---|
| 1 | Process Create | Finding the malicious process, parent, original filename, hashes |
| 2 | File creation time changed | Timestomping |
| 3 | Network connection | C2 / connectivity check IP |
| 5 | Process terminated | Process end time |
| 11 | FileCreate | Files dropped to disk |
| 15 | FileCreateStreamHash | Zone.Identifier (Mark of the Web), download origin |
| 22 | DNSEvent | Domain resolution |
| 23 | FileDelete (archived) | Cleanup / deleted files |

---

## Task 1: How many Event logs are there with Event ID 11?

Filtering on Event ID 11 (FileCreate) returns the total.

<img width="327" height="470" alt="image" src="https://github.com/user-attachments/assets/f5799ffa-cde3-4e94-82a4-573058c9ea67" />

**Answer:** `56` *(verify against your screenshot)*

---

## Task 2: What is the malicious process that infected the victim's system?

Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed.

Query targeting Sysmon 1 and Vn:

```
Event_id: 1 vn
```

This reduces the results to 2 events that should be investigated.

<img width="1074" height="359" alt="image" src="https://github.com/user-attachments/assets/4a973647-6de1-4d9d-a57b-3ceba713b96d" />

**Event 1:** This is evidence that the file originally had another name, `fattura 2 2024.exe`, and was renamed `Preventivo24.02.14.exe.exe`. It was executed by the user directly from the browser, with `explorer.exe` as parent. Mapped as MITRE `T1204` `User Execution`.

**Event 2:** This is evidence of the use of the legitimate installer tool `msiexec.exe`, `technique_id=T1218,technique_name=Signed Binary Proxy Execution`, with the intent of dropping `AppData\Roaming\Photo and Fax Vn\...`, another persistence mechanism or backdoor.

**Answer:** `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`

---

## Task 3: Which Cloud drive was used to distribute the malware?

I ran the query:

```
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe url
```

and retrieved the information of a Sysmon Event ID 15, `technique_id=T1189,technique_name=Drive-by Compromise`. The file was downloaded using the Firefox browser from a Dropbox domain. We could retrieve an IOC from that URL, but in a real environment blocking the domain shouldn't be the adequate solution.

<img width="1048" height="406" alt="image" src="https://github.com/user-attachments/assets/b1ee0027-5b75-4c35-b7eb-d1289067a22a" />

**Answer:** `dropbox.com`

---

## Task 4: What was the PDF file's timestamp changed to (Time Stomping)?

For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files.

Queried:

```
evend_id:2 pdf
```

and got one event, mapped as `technique_id=T1070.006,technique_name=Timestomp`. The file time was changed to 1 month earlier.

<img width="987" height="434" alt="image" src="https://github.com/user-attachments/assets/2ce98c0f-0a8b-4bad-aafc-eb11b76b92b5" />

**Answer:** `2024-01-14 08:10:06` *(verify against your screenshot)*

---

## Task 5: Where was "once.cmd" created on disk?

Querying:

```
once.cmd
```

retrieved 4 events: 2x Sysmon 11 (File Creation), 1 Sysmon 2 with the same evasion technique, TimeStomp, and Sysmon 23 for hashing. Scripts and payloads were identified.

<img width="728" height="647" alt="image" src="https://github.com/user-attachments/assets/730681b8-0d5e-4479-a3de-880169c7573f" />

Forder I checked the suspicious sysmon 23, File Delete, found a total of 16 files that the attacker tryed to hide, but that's alot of noise ^^'.

<img width="980" height="419" alt="image" src="https://github.com/user-attachments/assets/d4480893-03f9-450e-a1a5-5f6e99d8e313" />


**Answer:** `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Windows\System32\once.cmd` 

---

## Task 6: Which dummy domain did the malware try to reach?

The malicious file attempted to reach a dummy domain, most likely to check the internet connection status.

Queried for DNS querying: `event_id:22 
`

The latest event queried `www.example.com` and got a DNS resolution, which needs more investigation.

<img width="795" height="440" alt="image" src="https://github.com/user-attachments/assets/8dcdc2e1-415f-4834-a1ff-5287b5b0dc8f" />

**Answer:** `www.example.com`

---

## Task 7: Which IP address did the malicious process try to reach?

I checked for the possible network connection, querying Sysmon: `event_id:3 C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`

This retrieved 1 event, pointing to the previously queried DNS resolution over port 80, `technique_id=T1036,technique_name=Masquerading`, probable C2 server.

<img width="667" height="411" alt="image" src="https://github.com/user-attachments/assets/0058915f-0c35-4970-b444-c94525f6cddb" />

**Answer:** `93.184.216.34`

---

## Task 8: When did the malicious process terminate itself?

The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC.

Querying:`event_id:5  C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`

retrieved a single event, the end of the process.

<img width="999" height="31" alt="image" src="https://github.com/user-attachments/assets/6bdcaf24-a538-4024-8c47-1dfdecdde20e" />

**Answer:** `2024-02-14 03:41:58`

---

## Attack timeline

| Step | Activity | Event ID |
|---|---|---|
| 1 | User downloads the lure from Dropbox using Firefox | 15 |
| 2 | User runs `Preventivo24.02.14.exe.exe` from Downloads via explorer.exe | 1 |
| 3 | Dropper writes files to `AppData\Roaming\Photo and Fax Vn\...` | 11 |
| 4 | Timestomping on dropped files (PDF, `once.cmd`, etc.) | 2 |
| 5 | DNS lookup of `www.example.com` | 22 |
| 6 | TCP/80 connection to `93.184.216.34` | 3 |
| 7 | `msiexec.exe` runs the installer | 1 |
| 8 | Scripts deleted (16 files) | 23 |
| 9 | Dropper terminates itself at `2024-02-14 03:41:58` | 5 |

---

## MITRE ATT&CK mapping

### Analyst mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Resource Development | Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Payload hosted on Dropbox |
| Initial Access | Phishing: Spearphishing Link *(inferred)* | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Italian invoice/quote lure delivered as a download link; the delivery email is not in the logs, so this is inferred |
| Execution | User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User ran the file from Downloads via `explorer.exe` |
| Defense Evasion | Masquerading: Double File Extension | [T1036.007](https://attack.mitre.org/techniques/T1036/007/) | `Preventivo24.02.14.exe.exe` |
| Defense Evasion | System Binary Proxy Execution: Msiexec | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | `msiexec.exe` used to run the installer |
| Defense Evasion | Indicator Removal: Timestomp | [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Event ID 2 on the PDF and `once.cmd` |
| Defense Evasion | Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Event ID 23 on 16 files |
| Discovery | System Network Configuration Discovery: Internet Connection Discovery | [T1016.001](https://attack.mitre.org/techniques/T1016/001/) | DNS + TCP/80 to `example.com` (`93.184.216.34`) |
| Command and Control | Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | Backdoored UltraVNC (per Unit42 research and scenario) |


## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| File path | `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe` |
| Original filename | `fattura 2 2024.exe` |
| Drop directory | `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\` |
| Distribution | `dropbox.com` (specific URL in Event ID 15) |
| Domain | `www.example.com` (connectivity check) |
| IP | `93.184.216.34:80` |
| Termination time | `2024-02-14 03:41:58` |

## Detection ideas

- Alert on `explorer.exe` launching executables from `Downloads` that have double extensions.
- Alert on Sysmon Event ID 2 where `CreationUtcTime` is much older than `UtcTime`.
- Alert on `msiexec.exe` spawned from user-writable paths, or installing into `AppData\Roaming`.
- Hunt for unsigned binaries making DNS queries to `example.com`/`example.org` as a connectivity check.
- Review Event ID 15 `Zone.Identifier` data for executables downloaded from consumer cloud storage.

## Lessons learned

- Sysmon Event IDs 1, 2, 3, 5, 11, 15, 22 and 23 together reconstruct the full lifecycle of a dropper.
- `OriginalFileName` in Event ID 1 exposes renamed binaries.
- Event ID 15 shows where a file was downloaded from.
- Sysmon-provided technique tags are a starting point and should be re-mapped by the analyst.

## References

- Palo Alto Unit42: UltraVNC campaign research
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sysmon documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon)
