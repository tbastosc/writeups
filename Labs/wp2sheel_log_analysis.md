# wp2shell intrusion analysis from Apache, auth and filesystem artefacts

A walkthrough of how a **wp2shell** intrusion (CVE-2026-63030 + CVE-2026-60137) looks on a Linux WordPress server, reconstructed from a UAC triage image. It focuses on *where to look* and *which queries to run*, and uses relative times so the method can be reused on other cases.


## Executive summary

A single external host scanned a WordPress site, tried a short password list against `wp-login.php`, then used the wp2shell chain (REST `batch/v1` route confusion plus an `author__not_in` SQL injection) to create a temporary administrator, upload a malicious plugin and run commands as the web user. The temporary accounts and plugins were deleted by the exploit itself. The actor then moved to SSH as `root` using a reused password, added an SSH key for persistence, dumped every MySQL database to a file on disk and shut the host down.

| Milestone | Time |
|---|---|
| Reconnaissance begins (WPScan) | `T+00:00` |
| Password guessing against `wp-login.php` (45 attempts, all failed) | `T+00:42` to `T+00:44` |
| Exploitation begins (`/batch/v1`) | `T+05:52` |
| First OS-level command through the web shell | `T+06:46` |
| First temporary admin removed | `T+06:46` |
| Second temporary admin and web shell removed | `T+09:16` |
| First `root` SSH login | `T+13:48` |
| Database dump created / completed | `T+18:01` / `T+19:18` |
| SSH session ends | `T+24:25` |
| Host shut down | `T+30:28` |

## MITRE ATT&CK mapping

Enterprise ATT&CK, using the current release. Techniques seen in the evidence are **Observed**.

| Tactic | Technique | Status | Evidence |
|---|---|---|---|
| Reconnaissance | T1595.002 Active Scanning: Vulnerability Scanning | Observed | `WPScan v3.8.x` user agent, probes for `xmlrpc.php`, `debug.log`, `wp-config.php` backups |
| Credential Access | T1110.001 Brute Force: Password Guessing | Observed | 45 failed `POST /wp-login.php` in about three seconds (see the note on T1110.004 below) |
| Initial Access | T1190 Exploit Public-Facing Application | Observed | `POST /?rest_route=/batch/v1` with a `wp2shell` user agent |
| Persistence | T1505.003 Server Software Component: Web Shell | Observed | Plugins named `wp2shell_<hex>` under `wp-content/plugins/` |
| Execution | T1059.004 Unix Shell | Observed | Commands passed in the `c=` parameter of the web shell, and later in the root shell history |
| Discovery | T1082, T1083, T1057 | Observed | `uname -a`, `ls -la /`, `ps aux` |
| Credential Access | T1552.001 Credentials In Files | Observed | `wp-config.php` is the source of the database credentials |
| Credential Access | T1003.008 `/etc/passwd` and `/etc/shadow` | Observed | `cat /etc/passwd` via web shell, `cat /etc/shadow` in the root history |
| Initial Access / Persistence | T1078.003 Valid Accounts: Local Accounts | Observed | Root SSH login with a password shared with the application |
| Persistence | T1098.004 SSH Authorized Keys | Observed | An RSA public key in the root account's `authorized_keys` |
| Defense Evasion | T1070.004 File Deletion, T1070 Indicator Removal | Observed | Plugins and `wp2_*` accounts deleted by the exploit; shell history reviewed |
| Collection | T1005 Data from Local System | Observed | Full MySQL dump written to disk |
| Impact | T1529 System Shutdown/Restart | Observed | `shutdown` at the end of the session |
| Command and Control, Exfiltration | none | Not observed | No outbound C2 or transfer logged; the dump stayed on disk |

**Notes on the mapping.**

- T1110.004 (Credential Stuffing) means replaying leaked credential pairs. A short WPScan wordlist is closer to T1110.001. Use whichever label your report or exercise expects, but say what the log supports.
- Faking a date inside the injected row is part of the exploit mechanics (T1190), not data manipulation on its own, so it is not mapped to T1565.
- The `wp2shell_*` plugin name is distinctive rather than disguised, so T1036 (Masquerading) is not used.

## Kill chain

```text
Reconnaissance            T1595.002   WPScan
        |
        v
Password guessing         T1110.001   all attempts failed
        |
        v
Exploit public-facing app T1190       wp2shell batch route confusion -> SQLi
        |
        v
Web shell                 T1505.003   wp2shell_<hex> plugin
        |
        v
Command execution         T1059.004   id, uname, ls, ps, cat
        |
        v
Discovery                 T1082 / T1083 / T1057
        |
        v
Credential access         T1552.001 / T1003.008
        |
        v
SSH key persistence       T1098.004
        |
        v
Valid accounts            T1078.003   root over SSH
        |
        v
Collection                T1005       full database dump
        |
        v
Impact                    T1529       shutdown
```

## Evidence gathering

### 1. Reconnaissance (Apache access log)

Start with the Apache `access.log*` files. The first request from the attacker's IP identifies the scanner by its user agent, and the paths it probes show what it was looking for: `xmlrpc.php`, `debug.log`, `wp-config.php` backups and feeds.

```bash
grep -h '<attacker-ip>' access.log* | head -3 | cut -c1-250
grep -h 'WPScan' access.log* | awk '{print $1}' | sort | uniq -c
```

<img width="1281" height="532" alt="Figure 1 - first requests from the scanner" src="https://github.com/user-attachments/assets/88913044-13e7-4ba0-9ad4-75965d50673e" />

### 2. Password guessing

Count the scanner's POSTs to the login form, and separate them from its XML-RPC probes, which are not password attempts here. Response codes tell you the outcome: a failed login returns 200 with the form again, a successful one returns 302.

```bash
grep -h 'WPScan' access.log* | grep -c 'POST /wp-login.php'
grep -h 'WPScan' access.log* | grep 'POST /wp-login.php' | awk '{print $9}' | sort | uniq -c
```

<img width="1021" height="43" alt="Figure 2 - count of login POSTs" src="https://github.com/user-attachments/assets/1b642579-3d02-4e44-be5b-011266907b0a" />

### 3. Exploitation and the CVEs

Searching the access log for the second user agent shows the exploit traffic. A `wp2shell` agent hitting `/?rest_route=/batch/v1`, followed by a login, a plugin upload and then requests to a new plugin file, is the signature of the chain. Open-source write-ups tie this to **CVE-2026-63030** (REST batch route confusion) and **CVE-2026-60137** (`author__not_in` SQL injection), a core WordPress chain from July 2026.

```bash
grep -h 'wp2shell' access.log* | awk '{print $4,$6,$7,$9}' | head -60
grep -hc 'batch/v1' access.log*
```

<img width="1058" height="433" alt="Figure 3 - exploit traffic" src="https://github.com/user-attachments/assets/4e790221-b275-470c-95a2-3f52b741a8f6" />

### 4. SQL injection details (WordPress debug log)

Request bodies do not appear in the access log. If WordPress debug logging is on, `wp-content/debug.log` may keep the injected query. In this case it held the UNION payload, with several values hex-encoded.

<img width="1058" height="121" alt="Figure 4 - injected UNION query in debug.log" src="https://github.com/user-attachments/assets/42a9d974-eb02-43fe-b717-7c27d0af7d0d" />

Decode the hex values (for example in CyberChef, using *From Hex*). Several of them are fixed values placed into a forged row, including a hard-coded date in the past. That is a good indicator on its own, because legitimate posts do not carry it.

<img width="683" height="869" alt="Figure 5 - decoding the hex values" src="https://github.com/user-attachments/assets/a79f1621-5af0-4f36-a2b4-f8X0febef31" />

### 5. First code execution

The attacker logs in as the temporary administrator (a 302 from `wp-login.php`), uploads a plugin through `update.php?action=upload-plugin`, then calls the new plugin file with a command in the URL. The first request that returns command output is the first OS-level execution.

```bash
grep -h '<attacker-ip>' access.log* | grep 'c=id'
```

<img width="1279" height="205" alt="Figure 6 - first command request" src="https://github.com/user-attachments/assets/d4226c9d-ad87-4a6b-b7de-f74ac91d9d55" />

### 6. The web shells

List every plugin path requested by the attacker. There are two uploads here: the first runs one command and is removed within seconds, the second stays about two minutes and runs the interactive commands. Both clean up after themselves, so the plugin folders will not exist in the image; the access log is the evidence.

```bash
grep -ho 'plugins/wp2shell_[0-9a-f]*/wp2shell_[0-9a-f]*\.php' access.log* | sort | uniq -c
grep -ho 'delete_user=[^& ]*' access.log*
grep -h 'wp2shell_.*&c=' access.log* | grep -o '&c=[^ ]*' \
  | python3 -c "import sys,urllib.parse as u;[print(u.unquote_plus(l.strip()[3:])) for l in sys.stdin]"
```

<img width="1278" height="58" alt="Figure 7 - shell paths" src="https://github.com/user-attachments/assets/7af2b926-dd6e-4f61-9bc1-28d3849a0a99" />

### 7. SSH login with a privileged account

Search `auth.log*` for the attacker's IP. A successful `Accepted password` or `Accepted publickey` for `root` shortly after the web activity, from the same IP, suggests the password was reused between the application and the system. Confirm which account's password was reused using the credentials in `wp-config.php` and the `wp_users` data.

```bash
grep -h '<attacker-ip>' auth.log* | cut -c1-250
grep -hE 'Accepted (password|publickey)' auth.log* | awk '{print $1,$2,$3,$9,$11}'
```

<img width="1121" height="206" alt="Figure 8 - privileged login in auth.log" src="https://github.com/user-attachments/assets/94bfd0bc-1afb-44bc-a192-974e94c149c2" />

### 8. Persistence

Candidate persistence locations to check, in order:

- `/root/.ssh/authorized_keys` and other users' `authorized_keys`
- `/etc/cron.d/*`, `/var/spool/cron/crontabs/*`, `/etc/crontab`
- `/etc/systemd/system/*.service` and `*.timer`, `/etc/rc.local`
- `wp-content/mu-plugins/*.php` (a quiet place for a PHP backdoor)
- `/tmp` and `/var/tmp`

Use the bodyfile to find files changed after the first exploit request:

```bash
S=$(date -u -d '<first-exploit-time>' +%s); E=$(date -u -d '<shutdown-time>' +%s)
awk -F'|' -v s=$S -v e=$E '($9>=s&&$9<=e)||($10>=s&&$10<=e)||($11>=s&&$11<=e){print $2,$9,$10,$11}' bodyfile.txt \
  | grep -vE '^/(proc|sys|run|var/log|var/lib/(dpkg|apt))' | sort -k3
```

An SSH key's final field is normally `user@hostname`, which can identify the attacker's machine. Treat it as a lead, since the comment is free text and easy to change.

<img width="1269" height="86" alt="Figure 9 - authorized_keys contents" src="https://github.com/user-attachments/assets/506a0c99-f2e9-4f30-bc46-fb75fc6e2715" />

### 9. What the attacker did as root

The root shell history gives the best view of the later activity and is what ties each action to an ATT&CK technique. It shows the credential reads, system discovery, the database dump and the shutdown.

<img width="595" height="210" alt="Figure 10 - root shell history" src="https://github.com/user-attachments/assets/1af94aac-1ee2-4043-9b58-7efa6ba794fe" />

### 10. Timing the database dump

The exact second comes from the dump file's entry in `bodyfile/bodyfile.txt`. The bodyfile columns are:

```text
MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
```

Here `crtime` is when the file was created (the dump started) and `mtime` is when the last write finished (the dump ended). The epochs must be converted to UTC:

```bash
date -u -d @<epoch> '+%F %T UTC'
```

<img width="756" height="175" alt="Figure 11 - bodyfile entry for the dump" src="https://github.com/user-attachments/assets/ee4502b4-4caa-48b0-ab71-f74851844311" />

<img width="1269" height="154" alt="Figure 12 - epoch conversion" src="https://github.com/user-attachments/assets/3755118c-9331-4e99-9e01-cdc233e1e22b" />

## Detection ideas

**Apache or nginx access log (Sigma-style):**

```yaml
title: WordPress REST batch endpoint abuse (wp2shell pattern)
logsource: { category: webserver }
detection:
  batch:
    cs-method: POST
    cs-uri-query|contains: 'rest_route=/batch/v1'
  batch_path:
    cs-method: POST
    cs-uri-stem|endswith: '/wp-json/batch/v1'
  plugin_upload:
    cs-method: POST
    cs-uri-query|contains: 'action=upload-plugin'
  condition: batch or batch_path or plugin_upload
level: high
```

**Other signals:**

- Administrator accounts matching `wp2_*` or `w2s_*`, especially ones deleted within minutes.
- New plugin directories followed by a request with a `c=` parameter.
- A fixed, past `post_date` in forged rows, and `oembed_cache` or `customize_changeset` rows with unusually high IDs.
- An SSH login for `root` from an IP that was seen scanning the web application minutes earlier.
- A `.sql` file created in a root-owned directory outside backup paths.

## Hardening and lessons learned

1. Patch WordPress core to the fixed releases for the 6.8, 6.9 and 7.0 branches.
2. Block unauthenticated access to `/wp-json/batch/v1` and `?rest_route=/batch/v1` at the web server or WAF until patched.
3. Never reuse passwords between the application, the database account and system accounts. Disable root password login over SSH and use keys.
4. Switch off `WP_DEBUG` and `WP_DEBUG_LOG` in production, and keep `debug.log` out of the web root, since it exposed query details.
5. Forward web, auth and audit logs off the host. A shutdown and the self-cleaning exploit leave little on disk.
6. Remember that the exploit removes its own admin account and plugin, so their absence does not mean no compromise.

## References

- Picus Security, [CVE-2026-63030 and CVE-2026-60137 (wp2shell): WordPress RCE explained](https://www.picussecurity.com/resource/blog/cve-2026-63030-and-cve-2026-60137-wp2shell-wordpress-rce-explained)
- Eye Security, [wp2shell: incident response guide](https://labs.eye.security/wp2shell-defenders-guide/)
- F5 Labs, [CVE-2026-63030 and CVE-2026-60137 (wp2shell): captured exploit payload](https://www.f5.com/labs/articles/cve-2026-63030-and-cve-2026-60137-wp2shell-captured-exploit-payload)
