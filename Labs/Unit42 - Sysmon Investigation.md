This  investigation is a walktrouh for Unit42 sherlok from HTB. The base for this investigation is the use os Sysmon.

Task 1 : How many Event logs are there with Event ID 11?

<img width="327" height="470" alt="image" src="https://github.com/user-attachments/assets/f5799ffa-cde3-4e94-82a4-573058c9ea67" />

Task 2 : Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?

Querie targeting sysmon 1 and Vn, `Event_id: 1 vn` we reduce to 2 events that should be investigated.

<img width="1074" height="359" alt="image" src="https://github.com/user-attachments/assets/4a973647-6de1-4d9d-a57b-3ceba713b96d" />

This is evidence that the file has a another name originaly `fattura 2 2024.exe`, renamed `Preventivo24.02.14.exe.exe`, and was executed by the user directly from the Browser explorer.exe. Mapped as Mitre T=1204 `User Execution`.
Se second event it's evidence of using legitimate installer tool `msiexe.exe` , `technique_id=T1218,technique_name=Signed Binary Proxy Execution`, with the intent of to dropped `AppData\Roaming\Photo and Fax Vn\...` other persistence mekanism or backdoor.

Answer: C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe

Task 3 : Which Cloud drive was used to distribute the malware?

I run querie for `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe url`, and retrieved information, of a Sysmon Event = 15, `technique_id=T1189,technique_name=Drive-by Compromise`, the file used Firefox Browser to download from a domain Dropbox, we could retrieve a IOC from that URL, but in real invornment blocking the doamin should't be the addequate solution.

<img width="1048" height="406" alt="image" src="https://github.com/user-attachments/assets/b1ee0027-5b75-4c35-b7eb-d1289067a22a" />

Answer:dropbox.com

Task 4 : For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files. What was the timestamp changed to for the PDF file?

Queried `evend_id:2 pdf`, got one event, mapped as ` technique_id=T1070.006,technique_name=Timestomp`, the file time was changed to 1 moth erlier.

<img width="987" height="434" alt="image" src="https://github.com/user-attachments/assets/2ce98c0f-0a8b-4bad-aafc-eb11b76b92b5" />

Task 5 : The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename.

quering `once.cmd`, retrieved 4 events, 2x sysmon 11 <file Creation, 1 sysmon 2, with the same technique of evation TimeStomp and sysmon 23 for hashing, was identified scripts and payloads.

<img width="728" height="647" alt="image" src="https://github.com/user-attachments/assets/730681b8-0d5e-4479-a3de-880169c7573f" />



Task 6 : The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?

Queried for `event_id:22 ` Dns quering, the latest event queried `www.example.com`  and got a DNS resolution, that need more investigation.

<img width="795" height="440" alt="image" src="https://github.com/user-attachments/assets/8dcdc2e1-415f-4834-a1ff-5287b5b0dc8f" />

Answer: www.example.com

Task 7 : Which IP address did the malicious process try to reach out to?

I checked for the possible network connection, quering, sysmon `event_id:3 C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`, retrieved 1 event, pointing to the previous DNS queried resolution over port 80, technique_id=T1036,technique_name=Masquerading, provable C2 server:

<img width="667" height="411" alt="image" src="https://github.com/user-attachments/assets/0058915f-0c35-4970-b444-c94525f6cddb" />

Answer: 93.184.216.34

Task 8 : The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?

Quering ` event_id:5  C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe` retrieve a single event, end off the process.

<img width="999" height="31" alt="image" src="https://github.com/user-attachments/assets/6bdcaf24-a538-4024-8c47-1dfdecdde20e" />

Answer: 2024-02-14 03:41:58



