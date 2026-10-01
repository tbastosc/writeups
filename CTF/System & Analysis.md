codelivly CTF chellange - System & Analysis

# 1  # PrivEsc Audit — Find the Root Path

By performing post-compromise enumeration via `sudo -l`, we discovered that the low-privileged web user was granted passwordless execution rights over `/usr/bin/tar`, enabling a direct path to root privilege escalation.

<img width="789" height="774" alt="image" src="https://github.com/user-attachments/assets/2407f2a1-7d42-4491-99b0-63810412c853" />

**MITRE ATT&CK:** Privilege Escalation (`TA0004`) / Abuse Elevation Control Mechanism: Sudo and Sudo Caching (`T1548.003`)

Checking GTFOBins `tar` can be exploited by:
<img width="819" height="343" alt="image" src="https://github.com/user-attachments/assets/9c80730f-b61a-486d-aac5-0c3d80f6bcd9" />

Fix: Strictly enforce the principle of least privilege by avoiding overly permissive `sudo` configurations; never grant service accounts root-level execution rights for binaries like `tar` that can be leveraged to escape restrictions or read/write sensitive system files.

# 2 # Docker Escape Audit — Spot the Misconfig

By analyzing the container configuration via `docker inspect`, we identified a dangerous volume mount exposing the Docker daemon socket (`/var/run/docker.sock`). giving an application container access to the host's container-management API, which is equivalent to granting it root on the host
**MITRE ATT&CK:** Privilege Escalation (`TA0004`) / Escape to Host (`T1611`)

<img width="508" height="367" alt="image" src="https://github.com/user-attachments/assets/22c869c3-2995-4c98-9b44-efd6ad025b52" />

Fix: Never mount the host's Docker socket (`docker.sock`) inside a container unless absolutely necessary, as it grants root-equivalent control over the entire Docker daemon and host system; instead, use secure, isolated CI/CD pipelines or alternative container management architectures.
