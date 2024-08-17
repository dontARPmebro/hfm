## output contents of file

`echo “$(<file.txt)”`

## display lines 510-520 of file

`sed -n '510,520p' /etc/neo4j/logs/debug.log`

## Clear history

`echo " " > ~/.zsh_history`

## Remove Whitespace and Carriage Returns

`sed ':a;N;$!ba;s/\n//g' hash > hash_cleaned`

Whitespace

    tr -d ' ' < input.txt > no-spaces.txt
    tr -d '[:blank:]' < input.txt > no-spaces.txt
    tr -d '[:space:]' < input.txt > no-spaces.txt

Carriage return

`sed 's/\r$//' file.txt > out.txt.`
`tr -d '\r' input.txt > out.txt.`

## Enable SSH
If you only need to temporarily start up the SSH service it’s recommended to use ssh.socket:

```
systemctl start ssh.socket
```

When finished:

```
systemctl stop ssh.socket
```

To instead permanently enable the SSH service to start whenever the system is booted use:

```
systemctl enable ssh.service
```

Then to use SSH immediately without having to reboot use:

```
systemctl start ssh.service
```

To check the status of the service you can use:

```
systemctl status ssh.service
```

To stop the SSH service use:

```
systemctl stop ssh.service
```

And to disable the SSH service so it no longer starts at boot:

```
systemctl disable ssh.service
```
From <[https://www.lmgsecurity.com/enable-start-ssh-kali-linux/](https://www.lmgsecurity.com/enable-start-ssh-kali-linux/)>

check port status

```
netstat -tulpn
```