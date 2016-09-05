#!/usr/bin/python
'''
The purpose of this script is to check for weak ciphers on a remote SSH server

the script defines the good ciphers as mentioned in the advice here
https://wiki.mozilla.org/Security/Guidelines/OpenSSH

===================================================
		Usage
python SSHciphers.py <ip address>
e.g. python SSHCiphers.py

====================================================

Note this script is effectivly just a parser for nmap

the nmap script we use here hard codes that SSH scanning is done on port 22/tcp
if you need to change this you need to modify the namp script - recomend copying and renaming the copy. use the copy
leave the original entact

the line that needs modified is

portrule = shortport.port_or_service(22, "ssh")

in kali is /usr/share/nmap/scripts/ssh2-enum-algos.nse




'''


# import our modules
import sys
import subprocess

# lets build our selves a debug mode
DEBUG = False  # set to True or False
#DEBUG = True

# declare our variables and sets
#host = sys.argv[1]
host=sys.argv[1]
KexAlgorithms = ['curve25519-sha256@libssh.org', 'ecdh-sha2-nistp521', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp256', 'diffie-hellman-group-exchange-sha256']
MACs = ['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-512','hmac-sha2-256', 'umac-128@openssh.com']
Ciphers = ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr','aes192-ctr', 'aes128-ctr']
Headers = ['kex_algorithms','server_host_key_algorithms','encryption_algorithms','mac_algorithms','compression_algorithms']
l_printed = []
bad_count = 0


print "==============================================================="
print "=         SSH Cipher Check for", host
print "==============================================================="

# To check for ciphers we're goping to use NMap - no need to reinvet the wheel


if len(host) < 2:

    print('Please provide a ip address or a hostname!\n')
    print('Usage: python SSHCiphers.py <IP_Address>\n')
    print('Example: python SSHCiphers.py 8.8.8.8\n\n')
    sys.exit()

else:
    #print "\n"
    nmapout = subprocess.check_output(["nmap", "-Pn", "-p 22 ", host, "--script", "ssh2-enum-algos"])

    nmapout = nmapout.replace("Nmap scan report for ", "Host: ").replace("22/tcp open  ssh", "")
    nmapout = nmapout.replace("|       ", "").replace("PORT   STATE SERVICE", "").replace("|   ","")
    nmapLinesList = nmapout.splitlines()
    for line in nmapLinesList:
        line = line.strip()
        if DEBUG:
            print line

        if line.startswith("kex_algorithms"):
            print "=== Kex Algorithms ==="
            l_printed.append(line)


        if line.startswith("mac_algorithms:"):
            print "\n=== Mac Algorithms:==="
            l_printed.append(line)

        if line.startswith("encryption_algorithms:"):
            print "\n=== Encryption Algorithms:==="
            l_printed.append(line)

        #if line.startswith("compression_algorithms:"):
         #   print "\n\n=== Compression Algorithms:==="
          #  l_printed.append(line)

        if line.lower().startswith(("host","starting","|","nmap", "none","server_host_key","ssh-rsa","ssh-rsa","compression_algorithms")):
            line = ""

        if line not in l_printed and len(line) > 2 and line not in Headers and line not in Ciphers and line not in KexAlgorithms and line not in MACs:
            print line
            bad_count = bad_count+1

print "============================="
print "     Scan finished"
print "     Total Issues: ", str(bad_count)
print "============================="
print
print
