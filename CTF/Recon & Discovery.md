Walktrough ctf challenge from codelivly

Recon and Discovery falls into Mitre Attack tactics as xxxxx

# 1 # **Developer Notes**

Developers tend to make notes on its source code, most of times nothing that comprimisse, but could be also a risk of leak confidential information, source code should always be sanitized before deploynment.

<img width="873" height="306" alt="image" src="https://github.com/user-attachments/assets/82598201-3689-4775-a5e1-4dc39b44523c" />

Notes have no use for public!

# 2 # Robots Explorer

While robots.txt is useful for managing search indexers, using robots.txt is only good practice for keeping out search engines from non-sensitive, public pages relying on it to hide sensitive directories creates a false sense of security by inadvertently advertising private paths to malicious actors.

<img width="563" height="178" alt="image" src="https://github.com/user-attachments/assets/72d77ba1-60c7-4deb-8a9f-94de4ae69c2c" />

<img width="460" height="403" alt="image" src="https://github.com/user-attachments/assets/0192cce6-4400-4b66-9bbb-7ec3bc879ee1" />

Notes have no use for public! Always remember to rotate the deploy token before launch.


# 3 # Hidden Sitemap

While standard website navigation only exposed a handful of pages, inspecting sitemap.xml revealed an unlinked, hidden endpoint that wasn't reachable through normal browsing.

<img width="591" height="312" alt="image" src="https://github.com/user-attachments/assets/14076a77-5ebe-453b-92c2-21c8604e5da8" />
<img width="700" height="312" alt="image" src="https://github.com/user-attachments/assets/01a246d8-ff8f-4635-aa70-ec328dd494a8" />

Remove the unlinked page from sitemap.xml and secure it behind proper authentication, as obscurity is not security.

# 4 # README Leak

Never deploy internal documentation, configuration files, or code repository artifacts (like README or .git folders) to the production web root; ensure deployment scripts exclude non-public files.

<img width="677" height="368" alt="image" src="https://github.com/user-attachments/assets/ee5bd6bf-a3a4-4f25-9480-039a8d4563e2" />


