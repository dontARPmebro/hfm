[[Index.canvas|Index]]

## Web Server Enumeration

## Directory & Page Fuzzing



## Subdomain & Virtual Host Fuzzing

### Subdomain Fuzzing
```
```
### Virtual Host Fuzzing
```
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u $URL -H "HOST: FUZZ.jab.htb"
```

## Parameter & Value Fuzzing



