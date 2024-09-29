## Information Gathering
### Ports/Services
```
sudo nmap -sT -sV -sC -O -p- -T4 --min-rate=1000 $IP  
```

```
autorecon $IP -v  
```

### Directories/Subdomain/Files
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
### Identify Web Technology

```
nikto -h $URL -C all
```
