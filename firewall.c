#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/netlink.h>

struct fw_rule{
    __be32 ip;
    __be16 port;
    __u8 protocol;
    struct list_head list;
};

#define PROC_ENTRY "/proc/block_list"
#define NETLINK_USER 31

static LIST_HEAD(rule_list);
static struct nf_hook_ops nfho;
static struct proc_dir_entry* proc_entry;
struct sock* nl_sk = NULL;

char* protocol_to_string(__u8 protocol){
    switch(protocol){
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        default:
            return "NO_PROTOCOL";
    }
}
unsigned int hook_func(void *priv,struct sk_buff *skb,const struct nf_hook_state *state){
    struct iphdr* ip_header;
    if(!skb) return NF_ACCEPT;
    ip_header = ip_hdr(skb);
    if(!ip_header) return NF_ACCEPT;
    struct fw_rule* rule;
    list_for_each_entry(rule, &rule_list, list){
        if(ip_header->protocol == IPPROTO_TCP){
            struct tcphdr* tcp_header = tcp_hdr(skb);
            if(rule->ip == ip_header->daddr && rule->protocol == ip_header->protocol && rule->port == tcp_header->dest){
                printk(KERN_INFO "Block IP :%pI4 ,Port :%d, Protocol :%s\n",&rule->ip,ntohs(rule->port),protocol_to_string(rule->protocol));
                return NF_DROP;
            }
        }else if(ip_header->protocol == IPPROTO_UDP){
            struct udphdr* udp_header = udp_hdr(skb);
            if(rule->ip == ip_header->daddr && rule->protocol == ip_header->protocol && rule->port == udp_header->dest){
                printk(KERN_INFO "Block IP :%pI4 ,Port :%d, Protocol :%s\n",&rule->ip,ntohs(rule->port),protocol_to_string(rule->protocol));
                return NF_DROP;
            }
        }else if(ip_header->protocol == IPPROTO_ICMP){
            if(rule->ip == ip_header->daddr && rule->protocol == ip_header->protocol){
                printk(KERN_INFO "Block IP :%pI4, Protocol :%s\n",&rule->ip,protocol_to_string(rule->protocol));
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

static void send_msg_to_user(int pid, const char* msg, int msg_len){
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int chunk_size, offset = 0;

    while (offset < msg_len) {
        chunk_size = min(msg_len - offset, 1024);  // 每次傳 1024 Bytes
        skb = nlmsg_new(chunk_size, GFP_KERNEL);
        if (!skb) {
            printk(KERN_ERR "Failed to allocate skb\n");
            return;
        }

        nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, chunk_size, 0);
        memcpy(nlmsg_data(nlh), msg + offset, chunk_size);

        if (netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT) < 0) {
            printk(KERN_ERR "Failed to send Netlink message\n");
        }

        offset += chunk_size;
    }
}

static void nl_recv_msg(struct sk_buff* skb){
    struct nlmsghdr* nlh;
    char* kbuf;
    char ip_str[64];
    int port;
    char protocol[8];
    char action[8];
    int user_id;
    struct fw_rule* new_rule;

    nlh = (struct nlmsghdr*)skb->data;
    kbuf = (char*)nlmsg_data(nlh);
    user_id = nlh->nlmsg_pid;

    if(strcmp("ls",kbuf) == 0){
        char* buf;
        int len = 0;
        struct fw_rule* rule;
        buf = vmalloc(16 * PAGE_SIZE);  // 分配較大的緩衝區
        if (!buf) {
            printk(KERN_ERR "Failed to allocate memory\n");
            return;
        }
        list_for_each_entry(rule, &rule_list, list){
            len += scnprintf(buf+len, 16*PAGE_SIZE - len, "IP: %pI4, Protocol: %s, Port: %d\n",&rule->ip, protocol_to_string(rule->protocol), ntohs(rule->port));
            if(len >= (16*PAGE_SIZE-1)) break;
        }
        if(len != 0){
            buf[len] = '\0';
            send_msg_to_user(user_id,buf,len);
        }else{
            strcpy(buf,"NO rule...\n");
            send_msg_to_user(user_id,buf,strlen("NO rule...\n"));
        }
        vfree(buf);
        return ;
    }
    else if(sscanf(kbuf,"%s %15s %d %7s",action,ip_str,&port,protocol)!=4){
        printk(KERN_ERR "input error\n");
        send_msg_to_user(user_id,"Input error\n",strlen("Input error\n"));
        return ;
    }
    if(strcmp("del",action) == 0){
        struct fw_rule* rule;
        __be32 del_ip = in_aton(ip_str);
        __be16 del_port = htons(port);
        list_for_each_entry(rule,&rule_list,list){
            if((rule->ip == del_ip) && (rule->port == del_port) && (strcmp(protocol,protocol_to_string(rule->protocol)) == 0)){
                list_del(&rule->list);
                kfree(rule);
                printk(KERN_INFO "Del rule IP = %s Port = %d Protocol = %s\n",ip_str,port,protocol);
                send_msg_to_user(user_id,"Delete successful\n",strlen("Delete successful\n"));
                return ;
            }
        }
        printk(KERN_INFO "Not Find rule.....\n");
        send_msg_to_user(user_id,"Not Find rule.....\n",strlen("Not Find rule.....\n"));
        return ;
    }
    new_rule = kmalloc(sizeof(*new_rule),GFP_KERNEL);
    new_rule->ip = in_aton(ip_str);
    new_rule->port = htons(port);

    if(strcmp(protocol,"TCP")==0){
        new_rule->protocol = IPPROTO_TCP;
    }else if(strcmp(protocol,"UDP")==0){
        new_rule->protocol = IPPROTO_UDP;
    }else if(strcmp(protocol,"ICMP")==0){
        new_rule->protocol = IPPROTO_ICMP;
        new_rule->port = 0;
    }else{
        kfree(new_rule);
        send_msg_to_user(user_id, "Protocol error\n",strlen("Protocol error\n"));
        printk(KERN_ERR "Protocol error\n");
        return ;
    }
    INIT_LIST_HEAD(&new_rule->list);
    list_add(&new_rule->list,&rule_list);
    printk(KERN_INFO "%s IP %s, Port %d Protocol %s\n",action,ip_str,port,protocol);
    send_msg_to_user(user_id, "Add successful\n",strlen("Add successful\n"));
}

static int __init fw_init(void){
    nfho.hook = hook_func;
    nfho.priority = NF_IP_PRI_FIRST;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nf_register_net_hook(&init_net, &nfho);

    struct netlink_kernel_cfg cfg={
        .input = nl_recv_msg,
    };
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if(!nl_sk){
        printk(KERN_INFO "Error create netlink\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "Firewall loaded....\n");
    return 0;
}

static void __exit fw_exit(void){
    nf_unregister_net_hook(&init_net, &nfho);
    struct fw_rule *rule, *tmp;

    // 清理鏈表中的規則
    list_for_each_entry_safe(rule, tmp, &rule_list, list) {
        list_del(&rule->list);
        kfree(rule);
    }

    netlink_kernel_release(nl_sk);
    printk(KERN_INFO "Firewall unloaded....\n");
}


module_init(fw_init);
module_exit(fw_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dennis");
MODULE_DESCRIPTION("Simple Firewall Module");