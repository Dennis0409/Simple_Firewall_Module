#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>

struct fw_rule{
    __be32 ip;
    __be16 port;
    __u8 protocol;
    struct list_head list;
};

#define PROC_ENTRY "/proc/block_list"
static LIST_HEAD(rule_list);
static struct nf_hook_ops nfho;
static struct proc_dir_entry* proc_entry;

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

static ssize_t proc_write(struct file* filp, const char __user* buf, size_t len, loff_t *ppos){
    char kbuf[64];
    char ip_str[64];
    int port;
    char protocol[8];
    char action[8];
    struct fw_rule* new_rule;

    if(len >= sizeof(kbuf)) return -EINVAL;
    if(copy_from_user(kbuf,buf,len)) return -EFAULT;

    kbuf[len]='\0';
    if(sscanf(kbuf,"%s %15s %d %7s",action,ip_str,&port,protocol)!=4) return -EINVAL;
    if(strcmp("del",action) == 0){
        struct fw_rule* rule;
        __be32 del_ip = in_aton(ip_str);
        __be16 del_port = htons(port);
        list_for_each_entry(rule,&rule_list,list){
            if((rule->ip == del_ip) && (rule->port == del_port) && (strcmp(protocol,protocol_to_string(rule->protocol)) == 0)){
                list_del(&rule->list);
                kfree(rule);
                printk(KERN_INFO "Del rule IP = %s Port = %d Protocol = %s\n",ip_str,port,protocol);
                return len;
            }
        }
        printk(KERN_INFO "Not Find rule.....\n");
        return len;
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
        return -EINVAL;
    }
    INIT_LIST_HEAD(&new_rule->list);
    list_add(&new_rule->list,&rule_list);
    printk(KERN_INFO "%s IP %s, Port %d Protocol %s\n",action,ip_str,port,protocol);
    return len;
}

static ssize_t proc_read(struct file* filp, char __user* buf, size_t count, loff_t* ppos){
    static int finish = 0;
    struct fw_rule* rule;
    char* kbuf;
    int len=0;

    if(finish){
        finish = 0;
        return 0;
    }
    kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    list_for_each_entry(rule, &rule_list, list){
        len += scnprintf(kbuf+len, PAGE_SIZE - len, "IP: %pI4, Protocol: %s, Port: %d\n",&rule->ip, protocol_to_string(rule->protocol), ntohs(rule->port));
        if(len >= PAGE_SIZE) break;
    }

    if(copy_to_user(buf,kbuf,len)) return -EFAULT;
    kfree(kbuf);
    finish = 1;
    return len;
}

static const struct proc_ops proc_op = {
    .proc_write = proc_write,
    .proc_read = proc_read,
};

static int __init fw_init(void){
    nfho.hook = hook_func;
    nfho.priority = NF_IP_PRI_FIRST;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nf_register_net_hook(&init_net, &nfho);

    proc_entry = proc_create(PROC_ENTRY,0666,NULL,&proc_op);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_ENTRY);
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
    remove_proc_entry(PROC_ENTRY,NULL);
    printk(KERN_INFO "Firewall unloaded....\n");
}


module_init(fw_init);
module_exit(fw_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dennis");
MODULE_DESCRIPTION("Simple Firewall Module");