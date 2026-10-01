Walktrough ctf challenge from codelivly

Recon and Discovery falls into MITRE ATT&CK tactics as TA0043/TA0007

# 1 # **Developer Notes**

Developers tend to make notes on its source code, most of times nothing that comprimisse, but could be also a risk of leak confidential information, source code should always be sanitized before deploynment.

<img width="873" height="306" alt="image" src="https://github.com/user-attachments/assets/3009bf7d-a9be-495e-b213-b399bd17b747" />


Notes have no use for public!

# 2 # Robots Explorer

While robots.txt is useful for managing search indexers, using robots.txt is only good practice for keeping out search engines from non-sensitive, public pages relying on it to hide sensitive directories creates a false sense of security by inadvertently advertising private paths to malicious actors.

<img width="563" height="178" alt="image" src="https://github.com/user-attachments/assets/83c0f7f7-dd04-4a98-8785-4ee71245faeb" />

Notes have no use for public! Always remember to rotate the deploy token before launch.


# 3 # Hidden Sitemap

While standard website navigation only exposed a handful of pages, inspecting sitemap.xml revealed an unlinked, hidden endpoint that wasn't reachable through normal browsing.

<img width="591" height="312" alt="image" src="https://github.com/user-attachments/assets/14076a77-5ebe-453b-92c2-21c8604e5da8" />
<img width="700" height="312" alt="image" src="https://github.com/user-attachments/assets/01a246d8-ff8f-4635-aa70-ec328dd494a8" />

Remove the unlinked page from sitemap.xml and secure it behind proper authentication, as obscurity is not security.

# 4 # README Leak

Never deploy internal documentation, configuration files, or code repository artifacts (like README or .git folders) to the production web root; ensure deployment scripts exclude non-public files.

<img width="677" height="368" alt="image" src="https://github.com/user-attachments/assets/ee5bd6bf-a3a4-4f25-9480-039a8d4563e2" />

# 5 # Git History

They gave us a package, inside was the source code, including the .hidden folder with git history. Even though the secret was removed from the latest code, inspecting the Git commit history with git log revealed the hardcoded API key (CLV{...}) from an early commit. Quite common mistake.

<img width="674" height="189" alt="image" src="https://github.com/user-attachments/assets/f544865b-70c8-4f7e-a6d7-5bb65c114890" />

Never hardcode secrets in source code, even temporarily; rewriting history or deleting a secret does not remove it from Git's log—use environment variables from day one and rotate any credentials that were ever committed.

# 6 # Metadata Hunter

By inspecting the embedded metadata of the downloaded brochure image using exiftool, we extracted sensitive information left in the file's comments, uncovering the hidden flag.

<img width="660" height="499" alt="image" src="https://github.com/user-attachments/assets/57b315fe-2dd9-4ad4-b75f-d3efdfc15f6b" />

Always strip hidden metadata, internal comments, and author details from public-facing media assets before deployment, as uncleaned files can inadvertently leak sensitive internal information. This risk can be mitigated using **`exiftool -all= -overwrite_original <imagename.ext>`**, effectively removing metadata and reducing file size.

# 7 # Log Explorer

By analyzing the verbose application logs exposed on the platform, we filtered through the noise to find an overly verbose debug line that accidentally leaked a sensitive session token/flag.

<img width="770" height="310" alt="image" src="https://github.com/user-attachments/assets/ec9f9496-b885-48d3-99c7-d0d2b53b6c85" />

Never log sensitive information, tokens, or personal data at the DEBUG or INFO levels; ensure logging mechanisms sanitize data and are restricted from public or unauthorized access.

