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

crackmapexec winrm $IP -u richard@compiled@htb -P /opt/useful/seclists/Passwords/xato-net-10-million-passwords-1000000.txt