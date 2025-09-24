# SmartMap — Focused Recon Script

SmartMap is a Bash wrapper around **Nmap** that automates common recon tasks:  
TCP/UDP port discovery, service/version detection, virtual host and subdomain enumeration, and Windows/AD hostname extraction.  
It is designed to make reconnaissance in HTB, penetration testing, and red-team scenarios faster, cleaner, and more structured.

---

## Features

- Full TCP sweep (1–65535) with automatic open port extraction
    
- UDP discovery (`--udp` top 200 / `--udp-full` all ports)
    
- Focused service/version scans (`-sCV` for TCP, `-sU -sV` for UDP)
    
- Pretty summary output in table format
    
- Virtual host hints extracted from HTTP redirects, TLS certs, SMB/LDAP/NTLM
    
- Auto-merge vhosts/hostnames into `/etc/hosts` (`--htb` mode)
    
- Subdomain/VHost bruteforce with `ffuf` or `gobuster`
    
- Windows/AD hostname discovery using `smb-os-discovery`, `ldap-rootdse`, `http-ntlm-info`
    
- Auto-save outputs in greppable, normal, and XML formats
    

---

## Requirements

Tested on Linux (Kali recommended). Dependencies:

- `bash` (>= 4.x)
    
- `nmap`
    
- `awk`, `sed`, `grep`
    
- `curl` (optional, for ffuf baseline filtering)
    
- `openssl` (optional, for TLS CN/SAN extraction)
    
- `ffuf` or `gobuster` (optional, for VHost brute-forcing)
    
