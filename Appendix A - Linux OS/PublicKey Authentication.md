**Set up your client**

1. Generate your key.
 ```
ssh-keygen
 ```
2. Configure ssh to use the key (on Kali).
 ```
 vim ~/.ssh/config
 ```
Your config file should have something similar to the following:
```
Host SERVERNAME
Hostname ip-or-domain-of-server
User USERNAME
PubKeyAuthentication yes
IdentityFile ./path/to/key
```

You can add `IdentitiesOnly yes` to ensure `ssh` uses the specified `IdentityFile` and no other keyfiles during authentication. Setting `IdentitiesOnly` prevents failed authentications from occurring, when `ssh` would otherwise attempt to login with multiple keys. Setting this is also considered more secure, as you're not leaking information about other keys you have installed, and maintaining separation of your keys between different levels of access.

3. Copy your key to your server.
  ```
  ssh-copy-id -i /path/to/key.pub SERVERNAME`
```
For example, `ssh-copy-id -i ~/.ssh/id_res.pub -p 22 user@1.1.1.1`

**Troubleshooting**

1. use "-vvv" option
2. Make sure the server has your PUBLIC key (.pub).
3. Make sure your IdentiyFile points to your PRIVATE key.
4. Make sure your `.ssh` directory has 700 and the files within are 600 permissions.
	- `ssh-keygen` will create files and directories for you with the proper permissions
1. `tail -f /var/log/auth.log` (on the server) and monitor errors when you attempt to login
2. If you have many key files, try `IdentitiesOnly yes` to limit the authentication to use the single, specified key.