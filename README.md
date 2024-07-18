# OrangeHeimer
## Network Diagram
![Orangeland Op Plan](https://github.com/user-attachments/assets/509ea69d-9de2-4575-a09f-db2846e0078a)
## Stage 1: Oranco Mining Web Server Exploitation
### Objective
- exploit web server and set up connection to internal relay SSH
### Files:
- orangeland.py	– metasploit module
- stage1.rc – metasploit rc file
### IPs and Ports:
- all can be customized in stage1.rc file
- thrower box	10.0.1.21:4444
- oranco Web	10.0.1.1:8443
- thrower SSH	127.0.0.1:22
- relay SSH	172.31.82.221:22
### How to Run:
- chmod +x orangeland.py
- move orangeland.py into metasploit-framework/embedded/framework/modules/exploits/unix/webapp/
- msfconsole -r exploit.rc -- may need to be run with sudo
### Possible Failures:
orangeland.py has been tested on multiple ops and should work, if it doesn’t, then verbally harass the analysts.
portfwd add is the only new command, if this fails:
- verify that the SSH server is running at the IP and port as indicated, if they are different, re run the portfwd command with -p <SSH_PORT> -r <SSH_IP>
- run shell in meterpreter, upgrade using python3 -c 'import pty; pty.spawn("/bin/bash")', and verify that the SSH credentials work
- run the portfwd command with a different thrower port using -l <THROW_PORT> Note, this means that all future SSH commands cannot use sshpass and must use -p <THROW_PORT>
