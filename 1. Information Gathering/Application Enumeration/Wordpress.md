[[Index.canvas|Index]]

## additional flags
```
-v -e --plugins-detection aggressive --api-token $(cat ~/Resource/wpscan_api_token) -o wpscan_results
```

## with API token
```
wpscan --url http://192.168.56.104/ --http-auth elliot:ER28-0652 --api-token QqoyStKXPlydupJbq5IDVOLxt16WvSSXrkj1Pas5gaY
```
## basic usage
```
wpscan --url "target" --verbose
```

## enumerate vulnerable plugins, users, vulrenable themes, timthumbs

```
wpscan --url "target" --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log
```

additional wpscan flags
```
wpscan --url "target" -v -e --plugins-detection aggressive --api-token $(cat ~/wpscan_api_token) -o wpscan_results

wpscan --url [http://192.168.56.104/](http://192.168.56.104/) --http-auth elliot:ER28-0652 --api-token QqoyStKXPlydupJbq5IDVOLxt16WvSSXrkj1Pas5gaY

wpscan --url "[http://$IP/wordpress/](http://$IP/wordpress/)" -v -e --plugins-detection aggressive --api-token $(cat ~/wpscan_api_token) -o wpscan_results

wpscan --url [http://10.10.10.9/wordpress -P /opt/SecLists/Passwords/Common-Credentials/500-worst-passwords.txt](http://10.10.10.9/wordpress%20-P%20/opt/SecLists/Passwords/Common-Credentials/500-worst-passwords.txt) -U admin threads 5 | tee wpscanLazy.txt
```

## Enumeration

Usernames

```
wpscan --url example.com --enumerate u
```

Vulnerable Plugins

`--enumerate vp`

Popular Plugins

`--enumerate p`

All Plugins

`--enumerate ap`

Vulnerable Themes

`--enumerate vt`

All Themes

`--enumerate at`

Popular Themes

`--enumerate t`

wp-config.php Backups

`--enumerate cb`

Database Exports

`--enumerate dbe`

## Password Brute Force

Supply list of passwords

```wpscan --url example.com -P passwords.txt```

Supply list of usernames

```wpscan --url example.com -U users.txt```

## Docker

Pull the repo

```
docker pull wpscanteam/wpscan
```

Enumerate Usernames

```
docker run -it --rm wpscanteam/wpscan --url
example.com --enumerate u
```
## Useful Flags

Supply custom wp-content Directory

`--wp-content-dir``

Random User Agent

`--random-user-agent`

Avoid Detection (limited checks)

`--stealthy`

Disable SSL/TLS Security

`--disable-tls-checks`

Disable WordPress Detection

`--force`

Set the Detection Mode

`--detection-mode [mixed|passive|aggressive]`

## Basics

Install WPScan

```
gem install wpscan
```

Update WPScan

```
gem update wpscan
```

Update local meta data

```
wpscan --update
```

Run simple scan

```
wpscan --url [www.example.com](http://www.example.com)
```

Supply API Token

`--api-token YOUR_TOKEN`
`