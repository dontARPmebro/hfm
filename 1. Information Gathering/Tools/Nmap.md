[[Index.canvas|Index]] 


```
for l in $(cat hosts);do sudo nmap -sV -sC -O -T4 -p- $l -oA $l-tcp;done 
```
## Host Discovery

## Port Scanning

## Saving Output

## Scripts

## Firewall and IDS/IPS Evasion

## Options


```
# Read the list of hosts from the text file
$hosts = Get-Content "hosts.txt"

# Define the Nmap command with desired arguments
$nmapCommand = "C:\path\to\nmap\nmap.exe -sS -sV -O -p- -oX"

# Iterate through each host and run Nmap
foreach ($host in $hosts) {
    $outputFile = "tcp-$host"
    $fullCommand = "$nmapCommand $outputFile $host"
    Invoke-Expression $fullCommand
}
```