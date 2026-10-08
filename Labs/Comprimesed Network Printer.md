

Com uma verificação ao conteudo do pcap, vemos muito trafego SYN, src 172.31.35.23 para dest. 172.31.40.241 em varias portas num curto espaço de tempo. Evidências de reconhecimento automatizado. As estatisticas confirmam a verificação.

<img width="819" height="271" alt="image" src="https://github.com/user-attachments/assets/63cc8a05-6acb-45a9-8bf1-67bb1f549ad2" />

Vamos validar se alguma porta deu resposta ACK(nolage), indicio de porta permitida.

'''
ip.src == 172.31.40.241&& tcp.flags.syn == 1 && tcp.flags.ack == 1
'''
Atacante descobriu a porta 22 e 9100 deram resposta positiva ao scan. SSH and Printer, port 9100 typically has no built-in security or password protection on the printer itself
<img width="734" height="152" alt="image" src="https://github.com/user-attachments/assets/975b806b-2198-4ea4-8a09-72f009a21221" />

Following tcp.stream from traffic to port 9100 confirm the type of asset, printer abused, PJL, HP LaserJet pro 4001dn. Evidence packet no.131177

<img width="549" height="445" alt="image" src="https://github.com/user-attachments/assets/48a1e026-f6ee-4fcf-8595-3744168abb25" />

The attacker started enumerating files using FSDIRLIST. Evidence packet no.131193
The attacker tryed to exfil a scheduled.ps1 file script, but got a error, eventually he corrected cmd the file name to scheduled.ps, and the file was exfiltered size=873 bytes

We can see the contentof the file :

<img width="763" height="715" alt="image" src="https://github.com/user-attachments/assets/1a260186-1104-4809-9557-810231198b36" />


Forther investigation using `ip.addr == 172.31.35.23 and tcp.port == 9100 && tcp.len>75` (>75) it's to cut down the noise.
Finding that the attacker used cmd FSDIRLIST, mapping the directories, found `internal.rdp` and `remote-service.ps1`. Evidence packet no. 132058.

<img width="635" height="316" alt="image" src="https://github.com/user-attachments/assets/98488454-bc4a-47f4-81c5-f309420acf8e" />

The attacker used FSQUERY and FSUPLOAD cmds to access the file internal.rdp, exfiltrating information. Evidence packet no. 132095.

<img width="679" height="829" alt="image" src="https://github.com/user-attachments/assets/14a117ed-c8f7-4207-b8c2-ae91e959fbb6" />

The attacker used FSQUERY and FSUPLOAD cmds to access the file remote-service.ps1, but we have no evidence of sucessfull exfiltration. Last package evidence no. 132147.













