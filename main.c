#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define PROC_ENTRY "/proc/block_list"

int rule(char* action, char* ip,char* port,char* protocol){
    int fd = open(PROC_ENTRY,O_WRONLY);
    if(fd < 0 ) return -1;
    char buf[64];
    int p = atoi(port);
    struct in_addr addr;
    int check = inet_pton(AF_INET,ip,&addr);
    if(check != 1){
        fprintf(stderr, "Invalid IP\n");
        return 1;
    }

    if(strcmp(protocol,"ICMP") == 0 && p != 0){
        fprintf(stderr, "ICMP Port must = 0\n");
        return 1;
    }

    if(p < 0 || p > 65535){
        fprintf(stderr, "Invalid Port\n");
        return 1;
    }

    if(strcmp("add",action) == 0){
        snprintf(buf,sizeof(buf),"add %15s %d %7s",ip,p,protocol);
    }
    else if(strcmp("del",action) == 0){
        snprintf(buf,sizeof(buf),"del %15s %d %7s",ip,p,protocol);
    }else{
        fprintf(stderr, "Invalid action(add or del)\n");
        return 1;
    }

    write(fd,buf,strlen(buf));
    close(fd);
    printf("%s rule IP: %s, Port: %d, Protocol: %s\n", action, ip, p, protocol);
    return 0;
}

void read_rule(){
    int fd = open(PROC_ENTRY,O_RDONLY);
    if(fd < 0) return -1;
    char buf[1024]={0};
    ssize_t bytes_read;
    //int r = read(fd, buf, 1024);
    while ((bytes_read = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[bytes_read] = '\0';  // 確保字串結尾
        printf("%s", buf);
    }
    if(bytes_read < 0){
        fprintf(stderr,"Read error\n");
        return ;
    }

    close(fd);
}

int main(int argc, char*argv[]){
    if(argc == 2 && strcmp("ls",argv[1]) == 0){
        read_rule();
        return 0;
    }
    if(argc != 5){
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s add <IP> <Port> <Protocol>   - Add rule\n", argv[0]);
        fprintf(stderr, "  %s del <IP> <Port> <Protocol>   - Delete rule\n", argv[0]);
        fprintf(stderr, "  %s ls                      - List all rules\n", argv[0]);
        return 1;
    }
    return rule(argv[1],argv[2],argv[3],argv[4]);
}