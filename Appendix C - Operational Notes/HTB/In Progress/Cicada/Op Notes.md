---
tags:
  - HTB
  - Seasonal
  - Linux
  - easy
creation date: 2018-09-29
Date Completed: 2024-08-24
CVEs: 
URL: 
IP: 10.129.192.218
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
53/tcp   open  domain        Simple DNS Plus
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
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

### SMB


![[Pasted image 20240928145423.png]]

![[Pasted image 20240928145339.png]]

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

### AutoRecon

CICADA-DC.cicada.htb

### Enumerating LDAP or trying to...

```
ldapsearch -x -H ldap://10.129.194.225 -D 'cicada.htb\info' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "DC=CICADA,DC=HTB"
```


```
# nothing
crackmapexec ldap 10.129.192.218 -d cicada.htb -u info -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)


```
# nothing
ldapdomaindump 10.129.194.225 -u 'CICADA.HTB\info' -p 'Cicada$M6Corpb*@Lp#nZp!8' --no-json --no-grep 
```

```
# nothing new
crackmapexec smb 10.129.192.218 -d cicada.htb -u info -p 'Cicada$M6Corpb*@Lp#nZp!8' -M spider_plus --share SYSVOL
```

```
# took too long
./kerbrute_linux_amd64 userenum -d CICADA.HTB --dc 10.129.192.218 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

```
# nothing
rpcclient //cicada-dc.cicada.htb -U domain.local/info%754d87d42adabcca32bdb34a876cbffb  --pw-nt-hash
```

```
# nothing
bloodhound-python -u 'info' -p 'Cicada$M6Corpb*@Lp#nZp!8' -ns 10.129.194.225 -d cicada.htb -c all
```

```
# nothing; requires bind
impacket-GetUserSPNs -dc-ip 10.129.194.225 'CICADA.HTB/info:Cicada$M6Corpb*@Lp#nZp!8'
```

```
./kerbrute_linux_amd64 passwordspray -d CICADA.HTB --dc 10.129.192.218 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt 'Cicada$M6Corpb*@Lp#nZp!8'
```

so ldap is out... requires bind... so quit trying ldap

```
# nothing
./udp-proto-scanner.pl 10.129.192.225
```

