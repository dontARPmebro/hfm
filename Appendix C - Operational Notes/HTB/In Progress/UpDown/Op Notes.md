---
tags:
  - HTB
  - Retired
  - Linux
creation date: 2022-09-03
Date Completed: 2024-08-24
CVEs: 
URL: https://app.hackthebox.com/machines/493
IP: 10.129.16.49
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)

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

