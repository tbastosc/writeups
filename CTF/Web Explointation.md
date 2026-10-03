> Under construction 

# 2 # Cookie Monster

Inspecting application storage via browser Developer Tools after authenticating with provided credentials. Located a cookie named session. Recognizing the text layout and potential padding (such as trailing = characters), identify it as Base64-encoded data rather than an encrypted token. Copying the string into a CyberChef reveals the underlying plaintext, exposing the sensitive flag or session payload.

**Mitre** Tactic: Credential Access (TA0006)
**Mitre Technique:** Steal Web Session Cookie (T1539)

<img width="788" height="185" alt="image" src="https://github.com/user-attachments/assets/ec4e6dbd-2f08-4f0e-8825-fe7b1eb19353" />


Fix: Replace insecure encoding with server-side sessions or cryptographically signed/encrypted tokens (such as JWE), and enforce HttpOnly, Secure, and SameSite cookie flags.

