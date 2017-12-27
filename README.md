# SSHCiphers
The purpose of this script is to use weak ciphers on remote SSH servers


# Who defined the good and bad ciphers
The script defines the good ciphers as mentioned in the advice from Mozilla, available here
https://wiki.mozilla.org/Security/Guidelines/OpenSSH

# Usage
python SSHciphers.py [IP ADDRESS]
e.g. python SSHCiphers.py 192.168.1.1

# Note
- this script is effectivly just a parser for nmap.
- the nmap script we use here hard codes that SSH scanning is done on port 22/tcp
- if you need to change this you need to modify the namp script - recomend copying and renaming the copy. use the copy
- leave the original entact
- the line that needs modified is
    portrule = shortport.port_or_service(22, "ssh")
-in kali is /usr/share/nmap/scripts/ssh2-enum-algos.nse
