#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netlink.h>

#define PROC_ENTRY "/proc/block_list"
#define NETLINK_USER 31

int netlink_send(char* action, char* ip,char* port,char* protocol){
    int sock_fd;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr* nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    char buf[64];

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if(sock_fd < 0){
        fprintf(stderr, "Socket create error\n");
        return 1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(1024));
    nlh->nlmsg_len = NLMSG_SPACE(1024);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    if(strcmp("ls",action)==0){
        strcpy(buf, "ls");
    }else{
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
    }
    
    strcpy(NLMSG_DATA(nlh), buf);

    iov.iov_base = (void*)nlh;
    iov.iov_len = nlh->nlmsg_len;

    msg.msg_name = (void*)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(sock_fd, &msg, 0);
    printf("Message sent to kernel\n");
    printf("Received from kernel :\n");
    int recv_len;
    while ((recv_len = recvmsg(sock_fd, &msg, 0)) > 0) {
        printf("%s", (char *)NLMSG_DATA(nlh));
        if (recv_len < 1024) break;  // 若接收長度小於 MAX_PAYLOAD，表示結束
    }

    close(sock_fd);
    free(nlh);
    return 0;
}

int main(int argc, char*argv[]){
    if(argc == 2 && strcmp("ls",argv[1]) == 0){
        netlink_send(argv[1],"","","");
        return 0;
    }
    if(argc != 5){
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s add <IP> <Port> <Protocol>   - Add rule\n", argv[0]);
        fprintf(stderr, "  %s del <IP> <Port> <Protocol>   - Delete rule\n", argv[0]);
        fprintf(stderr, "  %s ls                      - List all rules\n", argv[0]);
        return 1;
    }
    return netlink_send(argv[1],argv[2],argv[3],argv[4]);
}