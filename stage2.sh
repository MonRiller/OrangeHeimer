#!/bin/bash
# Change the interrupt key to k
stty intr ^k
# stage2.sh, sets up port forwarding on the orangeland relay server

# Change ssh server settings to enable port forwarding
sshpass -p 0rangel4nd ssh missileadmin@localhost "echo 0rangel4nd | sudo -S bash -c \"echo 'GatewayPorts yes' >> /etc/ssh/sshd_config\""
# Restart server to use settings
sshpass -p 0rangel4nd ssh missileadmin@localhost "echo 0rangel4nd | sudo -S service ssh restart"

# Wait to ensure restart
sleep 1

# Set up port forward going from thrower port 4200 to controller port 8080 IP format -- localhost:local_up:controller_ip:controller_up
sshpass -p 0rangel4nd ssh -Nf missileadmin@localhost -M -S ~/.ssh/masterSock -L 0.0.0.0:4200:172.31.86.120:8080
# Set up port forward going from SSH server 4242 to thrower port 4201 IP format -- relay_ip_from_controller:controller_down:localhost:local_down
sshpass -p 0rangel4nd ssh -Nf missileadmin@localhost -S ~/.ssh/masterSock -R 0.0.0.0:4242:127.0.0.1:4201
# Set up port forward going from SSH server 4243 to thrower port 4202 IP format -- relay_ip_from_controller:controller_down:localhost:local_down
sshpass -p 0rangel4nd ssh -Nf missileadmin@localhost -S ~/.ssh/masterSock -R 0.0.0.0:4243:127.0.0.1:4202
