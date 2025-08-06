# Password Hunting & Attacks

This repository is dedicated to techniques and tools used in **password discovery**, **extraction**, and **exploitation** across both **Windows** and **Linux** environments. It provides organized notes and examples for offensive security, red teaming, and penetration testing activities.

---

## 📌 Topics Covered

### 🔍 Password Hunting on Windows & Linux
- Locating stored credentials in local configuration files, scripts, environment variables, and memory.
- Common password file locations on Linux: `.bash_history`, `.git-credentials`, `/etc/shadow`, etc.
- Sensitive information in Windows registry, config files, and plaintext passwords in memory.

### 🔐 Password Cracking
- Offline password cracking using tools like `John the Ripper` and `Hashcat`.
- Wordlist and ruleset strategies.
- Cracking Windows hashes (NTLM, LM, etc.) and Linux hashes (MD5, SHA, bcrypt, etc.).
- PasswordManagers Cracking

### 🗂️ Password Hunting in Shares & Network
- Searching for credentials in exposed SMB shares, NFS mounts, FTP directories, and internal file servers.
- Automated scanning for common filename patterns like `passwords.txt`, `secrets.yml`, `.env`, etc.

### 🧪 Extracting Passwords from Windows
- Extracting credentials from:
  - **LSASS** (using tools like `Mimikatz`, `ProcDump`)
  - **NTDS.dit** (Active Directory database)
  - **SAM** (Security Account Manager)
  - **Credential Manager** and Vaults

### 🎭 Credential Replay Attacks
- **Pass-the-Hash (PtH)** – Reusing NTLM hashes to authenticate without cracking.
- **Pass-the-Ticket (PtT)** – Using extracted Kerberos tickets (TGT/TGS) to impersonate users.
- **Pass-the-Certificate** – Abusing certificate-based authentication with extracted private keys or smartcard credentials.


