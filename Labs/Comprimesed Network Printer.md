# HTB Sherlock: Compromised Network Printer

|                |                                                                                             |
| -------------- | ------------------------------------------------------------------------------------------- |
| **Platform**   | Hack The Box (Sherlocks)                                                                    |
| **Category**   | DFIR / Network traffic analysis (PCAP)                                                      |
| **Artifact**   | `capture.pcap` (SHA256: `0d06c022e8ba1e8f82c3f1ab912e27129b68871205c2a6acde87cd355256e9b5`) |
| **Tooling**    | Wireshark, PJL (Printer Job Language)                                                       |

## Executive Summary

An IDS alert flagged a network printer on the internal network as compromised. Analysis of the supplied packet capture shows that an internal host, `172.31.35.23`, scanned the printer (`172.31.40.241`, an HP LaserJet Pro 4001dn), found the SSH (`22`) and raw printing (`9100`) ports open, and abused **PJL** on port 9100 to browse the printer's file system and download files. The service required no authentication.

**What was exposed**

- `scheduled.ps` (873 bytes), a PostScript file disguised as an HR layoff notice, was exfiltrated.
- `internal.rdp` (1192 bytes), a backup Remote Desktop profile, was exfiltrated. It contains internal addresses (`172.31.23.97`, `13.122.16.11`) that give the attacker a next target for lateral movement.
- `remote-service.ps1` (685 bytes), a PowerShell automation script, was requested, but **there is no concrete evidence the transfer succeeded**.

**Impact and confidence**

- Confidentiality of the printer's stored jobs and of the jump host backups is compromised. No evidence of modification or persistence on the printer was found in this capture.
- Confidence is high for the scan, the open ports, the PJL activity and the two confirmed exfiltrations. It is lower for `remote-service.ps1`, which is treated as an attempt only.

**Recommended actions**

1. Isolate the printer and restrict TCP/9100 to legitimate print servers only.
2. Treat the contents of `internal.rdp` as exposed: review and rotate access to `172.31.23.97` and `13.122.16.11`.
3. Remove jump host backups from the printer's storage and investigate the source host `172.31.35.23`.

## Key Facts

| Item                | Value                                                                      |
| ------------------- | -------------------------------------------------------------------------- |
| Attacker host       | `172.31.35.23`                                                             |
| Victim (printer)    | `172.31.40.241`, HP LaserJet Pro 4001dn                                    |
| Open ports found    | `22/tcp` (SSH), `9100/tcp` (PJL / RAW printing)                            |
| Technique           | PJL commands `FSDIRLIST`, `FSQUERY`, `FSUPLOAD`                            |
| Confirmed exfil     | `scheduled.ps`, `internal.rdp`                                             |
| Unconfirmed         | `remote-service.ps1`                                                       |

## PJL Commands Used

| Command     | Usage in the incident                                                  |
| ----------- | ---------------------------------------------------------------------- |
| `FSDIRLIST` | List directories and map the printer's file system                     |
| `FSQUERY`   | Query a file (existence, size, errors) before extracting it            |
| `FSUPLOAD`  | Extract (exfiltrate) the content of a file                             |

---

## Investigation

### Step 1: Reconnaissance (port scan)

An initial look at the PCAP shows a large amount of **SYN** traffic from `172.31.35.23` to `172.31.40.241` across many ports in a very short time, which is evidence of **automated reconnaissance**. The capture statistics confirm it.

[![image](https://github.com/user-attachments/assets/63cc8a05-6acb-45a9-8bf1-67bb1f549ad2)](https://github.com/user-attachments/assets/63cc8a05-6acb-45a9-8bf1-67bb1f549ad2)

### Step 2: Open ports

To see which ports answered the scan, I filtered the **SYN/ACK** replies coming from the printer, which indicate open ports:

```
ip.src == 172.31.40.241 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

The attacker found that ports **22** and **9100** answered positively: **SSH** and the raw printing service (JetDirect). Port 9100 typically has no built-in security or password protection on the printer itself, which makes it an easy target.

[![image](https://github.com/user-attachments/assets/975b806b-2198-4ea4-8a09-72f009a21221)](https://github.com/user-attachments/assets/975b806b-2198-4ea4-8a09-72f009a21221)

**Answer:** ports `22` and `9100`

### Step 3: Asset identification (PJL)

Following the `tcp.stream` of the traffic to port 9100 confirms the type of asset being abused: an **HP LaserJet Pro 4001dn**, controlled through **PJL**.

**Evidence:** packet no. `131177`

[![image](https://github.com/user-attachments/assets/48a1e026-f6ee-4fcf-8595-3744168abb25)](https://github.com/user-attachments/assets/48a1e026-f6ee-4fcf-8595-3744168abb25)

### Step 4: File system enumeration

The attacker started enumerating files with `FSDIRLIST`.

**Evidence:** packet no. `131193`

From this point on, the following printer directories (root `0:/`) were explored:

| Directory                              | Description                                                                  |
| -------------------------------------- | ---------------------------------------------------------------------------- |
| `0:/`                                  | Root, with core system modules and backup stores                             |
| `0:/PJL`                               | Module directory associated with PJL execution structures                    |
| `0:/PostScript`                        | PostScript processing files                                                  |
| `0:/saveDevice`                        | Storage for saved jobs and configurations                                    |
| `0:/saveDevice/SavedJobs`              | Job management queues (`InProgress`, `KeepJob`)                              |
| `0:/saveDevice/SavedJobs/InProgress`   | Active or pending job files                                                  |
| `0:/saveDevice/SavedJobs/KeepJob`      | Persistent stored jobs                                                       |
| `0:/webServer`                         | Embedded web server root (`home`, `lib`, `objects`, `permanent`)             |
| `0:/webServer/home`                    | HTML files and manifests                                                     |
| `0:/webServer/lib`                     | Web server libraries (identified through the parent listing)                 |
| `0:/webServer/objects`                 | Web server objects (identified through the parent listing)                   |
| `0:/webServer/permanent`               | Persistent storage for the web interface                                     |
| `0:/backup`                            | System backup storage                                                        |
| `0:/backup/jumphost`                   | Configurations related to internal jump hosts                                |
| `0:/backup/jumphost/2023`              | Historical 2023 backup with sensitive scripts and RDP profiles               |

### Step 5: Exfiltration of `scheduled.ps`

The attacker tried to extract a file named `scheduled.ps1` and got an error. The command was then corrected to the real name, `scheduled.ps`, and the file was exfiltrated successfully (**873 bytes**).

The content is a **PostScript** file disguised as a layoff notice ("Jason LAYOFF NOTICE", attributed to HR), located in the job queue at `0:/saveDevice/SavedJobs/InProgress/`.

[![image](https://github.com/user-attachments/assets/1a260186-1104-4809-9557-810231198b36)](https://github.com/user-attachments/assets/1a260186-1104-4809-9557-810231198b36)

**Answer:** `0:/saveDevice/SavedJobs/InProgress/scheduled.ps` (873 bytes)

### Step 6: Discovery of internal access material

To cut down the noise, I filtered only the traffic with relevant payload (`tcp.len > 75`):

```
ip.addr == 172.31.35.23 and tcp.port == 9100 && tcp.len>75
```

This showed the attacker using `FSDIRLIST` to map the backup directory, where `internal.rdp` and `remote-service.ps1` were found.

**Evidence:** packet no. `132058`

[![image](https://github.com/user-attachments/assets/98488454-bc4a-47f4-81c5-f309420acf8e)](https://github.com/user-attachments/assets/98488454-bc4a-47f4-81c5-f309420acf8e)

### Step 7: Exfiltration of `internal.rdp`

The attacker used `FSQUERY` and `FSUPLOAD` on `internal.rdp` and extracted its content (**1192 bytes**). It is a Remote Desktop profile containing internal addresses, namely `172.31.23.97` and `13.122.16.11`, which gives the attacker a target for **lateral movement**.

**Evidence:** packet no. `132095`

[![image](https://github.com/user-attachments/assets/14a117ed-c8f7-4207-b8c2-ae91e959fbb6)](https://github.com/user-attachments/assets/14a117ed-c8f7-4207-b8c2-ae91e959fbb6)

**Answer:** `0:/backup/jumphost/2023/internal.rdp` (1192 bytes)

### Step 8: Attempt on `remote-service.ps1`

The attacker also used `FSQUERY` and `FSUPLOAD` on `remote-service.ps1` (**685 bytes**, a PowerShell automation script for a remote service). **There is no concrete evidence** that the exfiltration completed successfully, so it is treated as a probable but unconfirmed attempt.

**Evidence:** last relevant packet, no. `132147`

---

## Evidence Summary

### Packets

| Ref | Packet   | Finding                                                         | Command / Protocol     | Step |
| --- | -------- | --------------------------------------------------------------- | ---------------------- | ---- |
| E1  | `131177` | Asset identified as HP LaserJet Pro 4001dn                      | PJL (TCP/9100 stream)  | 3    |
| E2  | `131193` | Start of file system enumeration                                | `FSDIRLIST`            | 4    |
| E3  | `132058` | `internal.rdp` and `remote-service.ps1` discovered              | `FSDIRLIST`            | 6    |
| E4  | `132095` | `internal.rdp` queried and exfiltrated (1192 bytes)             | `FSQUERY` / `FSUPLOAD` | 7    |
| E5  | `132147` | `remote-service.ps1` requested, no proof of success             | `FSQUERY` / `FSUPLOAD` | 8    |

The scan (Step 1), the SYN/ACK replies (Step 2) and the `scheduled.ps` download (Step 5) were identified through statistics and display filters rather than a single packet reference.

### Hashes

| Item                                              | Type   | Hash                                                               |
| ------------------------------------------------- | ------ | ------------------------------------------------------------------ |
| `capture.pcap` (evidence file)                    | SHA256 | `0d06c022e8ba1e8f82c3f1ab912e27129b68871205c2a6acde87cd355256e9b5` |
| `scheduled.ps`, `internal.rdp`, `remote-service.ps1` | n/a | Not recorded: the extracted files were not carved from the PCAP    |

### Files consulted and exfiltrated

| File                                                | Size       | Content / Description                                                     | Action                          |
| --------------------------------------------------- | ---------- | ------------------------------------------------------------------------- | ------------------------------- |
| `0:/saveDevice/SavedJobs/InProgress/scheduled.ps`   | 873 bytes  | PostScript disguised as an HR layoff notice                               | Exfiltrated                     |
| `0:/webServer/home/device.html`                     | 165 bytes  | Device configuration page (web interface)                                 | Consulted / listed              |
| `0:/webServer/home/hostmanifest`                    | 230 bytes  | Web server host manifest                                                  | Consulted / listed              |
| `0:/backup/jumphost/2023/internal.rdp`              | 1192 bytes | RDP profile with internal IPs (`172.31.23.97`, `13.122.16.11`)            | Exfiltrated                     |
| `0:/backup/jumphost/2023/remote-service.ps1`        | 685 bytes  | PowerShell remote service script                                          | Attempted, no proof of success  |

---

## Attack Timeline

The capture is analyzed by packet number; absolute timestamps are not used in this writeup.

| Step | Packet   | Activity                                                              | Command / Protocol     |
| ---- | -------- | --------------------------------------------------------------------- | ---------------------- |
| 1    | n/a      | SYN scan across multiple printer ports                                | TCP                    |
| 2    | n/a      | Ports `22` and `9100` reply with SYN/ACK                              | TCP                    |
| 3    | `131177` | Asset identified: HP LaserJet Pro 4001dn                              | PJL                    |
| 4    | `131193` | File system enumeration begins                                        | `FSDIRLIST`            |
| 5    | n/a      | `scheduled.ps` exfiltrated (873 bytes) after correcting the file name | `FSUPLOAD`             |
| 6    | `132058` | `internal.rdp` and `remote-service.ps1` discovered                    | `FSDIRLIST`            |
| 7    | `132095` | `internal.rdp` exfiltrated (1192 bytes)                               | `FSQUERY` / `FSUPLOAD` |
| 8    | `132147` | Attempt on `remote-service.ps1`, no proof of exfiltration             | `FSQUERY` / `FSUPLOAD` |

## MITRE ATT&CK Mapping

| Tactic            | Technique                                                  | ID                                                          | Evidence                                                              |
| ----------------- | ---------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------- |
| Discovery         | Network Service Discovery                                  | [T1046](https://attack.mitre.org/techniques/T1046/)         | SYN scan across multiple ports of `172.31.40.241`                     |
| Discovery         | File and Directory Discovery                               | [T1083](https://attack.mitre.org/techniques/T1083/)         | `FSDIRLIST` over `0:/` and subdirectories                             |
| Collection        | Data from Local System                                     | [T1005](https://attack.mitre.org/techniques/T1005/)         | `FSUPLOAD` of `scheduled.ps` and `internal.rdp`                       |
| Exfiltration      | Exfiltration Over C2 Channel                               | [T1041](https://attack.mitre.org/techniques/T1041/)         | Extraction over the same TCP/9100 session used for the commands       |
| Credential Access | Unsecured Credentials: Credentials In Files *(potential)*  | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | RDP profile and jump host backup script; not confirmed                |

> The mapping is the analyst's own. T1041 and T1552.001 are interpretations; the others follow directly from the observed traffic.

## Indicators of Compromise (IOCs)

| Type                     | Value                                                              |
| ------------------------ | ------------------------------------------------------------------ |
| Attacker IP              | `172.31.35.23`                                                     |
| Printer IP               | `172.31.40.241` (HP LaserJet Pro 4001dn)                           |
| Ports                    | `9100/tcp` (PJL/RAW), `22/tcp` (SSH)                               |
| Exfiltrated file         | `0:/saveDevice/SavedJobs/InProgress/scheduled.ps`                  |
| Exfiltrated file         | `0:/backup/jumphost/2023/internal.rdp`                             |
| Attempted file           | `0:/backup/jumphost/2023/remote-service.ps1`                       |
| Exposed internal IPs     | `172.31.23.97`, `13.122.16.11` (contained in `internal.rdp`)       |
| PCAP hash (SHA256)       | `0d06c022e8ba1e8f82c3f1ab912e27129b68871205c2a6acde87cd355256e9b5` |

## Detection Ideas

- Alert on SYN scans across many ports from a single internal host toward printing devices.
- Restrict port `9100` to legitimate print servers and block it between user segments.
- Monitor PJL file system commands (`FSDIRLIST`, `FSQUERY`, `FSUPLOAD`) in traffic to port 9100.
- Detect TCP/9100 sessions where outbound traffic from the printer is far above normal.

## Lessons Learned

- Network printers are forgotten assets with access to sensitive data, and they must be part of the asset inventory and vulnerability management.
- Port 9100 has no authentication by default, which makes file system access through PJL straightforward.
- Configuration backups (such as RDP profiles and jump host scripts) should not be stored on the printer.
- Layered analysis (statistics, SYN/ACK filter, `tcp.stream`, `tcp.len` filter) cuts the noise in a large capture.

## References

- HTB Sherlocks: Compromised Network Printer
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
