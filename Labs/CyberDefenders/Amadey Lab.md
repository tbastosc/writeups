# Amadey Lab

Q1) In the memory dump analysis, determining the root of the malicious activity is essential for comprehending the extent of the intrusion. What is the name of the parent process that triggered this malicious behavior?

```bash
python3 vol.py -f memdmp.vmem windows.pslist
```

<img width="1116" height="596" alt="image" src="https://github.com/user-attachments/assets/a06040af-2e8f-4d33-af89-e62f356ae1cd" />

If the process name is misspelled ( **`lsaas.exe`->** **`lssass.exe`**, or similar), it is almost certainly malicious.

```bash
python3 vol.py -f memdmp.vmem windows.pstree
```
<img width="914" height="32" alt="image" src="https://github.com/user-attachments/assets/ff57cd42-0aa4-4438-9801-000809f025f4" />


it is **not normal** for `lsass.exe` to execute `rundll32.exe`. This behavior is suspicious and could indicate malicious activity, such as process injection or a technique used by malware to execute malicious code using `rundll32.exe`.

Answer:  lssass.exe

Q2) Once the rogue process is identified, its exact location on the device can reveal more about its nature and source. Where is this process housed on the workstation?

```bash
python3 vol.py -f memdmp.vmem windows.cmdline | grep "2748"
```

<img width="1054" height="37" alt="image" src="https://github.com/user-attachments/assets/ff474987-e117-4000-a139-c5d7562d994f" />

Answer: C:\Users\0XSH3R\~1\AppData\Local\Temp\925e7e99c5\lssass.exe

Q3) Persistent external communications suggest the malware's attempts to reach out C2C server. Can you identify the Command and Control (C2C) server IP that the process interacts with?

```bash
python3 vol.py -f memdmp.vmem windows.netscan | grep "2748"
```

<img width="1063" height="75" alt="image" src="https://github.com/user-attachments/assets/b25e55c8-fb55-4b7f-a1ff-4fde0353eeb8" />

Answer:  41.75.84.12

Q4) Following the malware link with the C2C, the malware is likely fetching additional tools or modules. How many distinct files is it trying to bring onto the compromised workstation?

```bash
strings memdmp.vmem | grep 'GET '
```

<img width="834" height="76" alt="image" src="https://github.com/user-attachments/assets/f8a3a402-7ac4-46b4-9f34-3df37e47fc0b" />

Answer:  2

Q5) Identifying the storage points of these additional components is critical for containment and cleanup. What is the full path of the file downloaded and used by the malware in its malicious activity?

```bash
python3 vol.py -f memdmp.vmem windows.cmdline | grep "clip64.dll"
#OR
python3 vol.py -f memdmp.vmem windows.filescan | grep "clip64.dll"
```

<img width="1133" height="92" alt="image" src="https://github.com/user-attachments/assets/339b159b-efc0-4da3-a59c-58d31c4bbc6f" />

Answer:  C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll

Q6) Once retrieved, the malware aims to activate its additional components. Which child process is initiated by the malware to execute these files?

```bash
python3 vol.py -f memdmp.vmem windows.pstree
```

<img width="1115" height="228" alt="image" src="https://github.com/user-attachments/assets/df1c7b65-f30d-4ed4-aea0-83f8626cae4b" />

Answer:  rundll32.exe

Q7) Understanding the full range of Amadey's persistence mechanisms can help in an effective mitigation. Apart from the locations already spotlighted, where else might the malware be ensuring its consistent presence?

```bash
python3 vol.py -f memdmp.vmem windows.filescan | grep "lssass.exe"
```
<img width="1199" height="75" alt="image" src="https://github.com/user-attachments/assets/344877ab-eeee-4379-b97a-1da80125994c" />


Answer:  C:\Windows\System32\Tasks\lssass.exe
