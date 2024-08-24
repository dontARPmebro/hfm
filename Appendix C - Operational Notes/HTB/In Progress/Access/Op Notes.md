---
tags:
  - HTB
  - Retired
  - Windows
creation date: ""
Date Completed: 2024-08-24
CVEs: 
URL: https://app.hackthebox.com/machines/Access
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T5 $IP  
```

```

```

### ffuf (Directories/Subdomain/Files)
```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ -u $URL/FUZZ
```

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt:FUZZ -u $URL/FUZZ
```

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u $URL -H "HOST: FUZZ.domain.htb"
```

### Nikto (Identify Technology)

