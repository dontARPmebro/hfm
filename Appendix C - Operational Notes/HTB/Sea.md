---
tags:
  - Linux
  - HTB
  - Season6
creation date: 2024-08-16T14:50:00
CVEs: 10.129.13.15
URL:
---
## Information Gathering
### Nmap
`sudo nmap -sT -sV -sC -O -p- -T5 $IP  `

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

### ffuf
```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ -u http://sea.htb/FUZZ 
```

There's a "contact" link on the "How to Participate" page
Click that and you'll find a form

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u $URL -H "HOST: FUZZ.jab.htb"
```

nothing from ffuf...

#### Testing form contact.php
i tried a bunch of shit in burp- injecting crap into every parameter
i even tried fuzzing for parameters
i tried entering my IP as the website URL - got nothing...
finally decided to pop over to 0xBEN and see what his hint was... turns out i was on the right track with using my IP as the web URL........

![[Pasted image 20240816165316.png]]
now to figure out the expoit....