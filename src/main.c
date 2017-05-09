#include "main.h"

static struct nf_hook_ops options;

static unsigned int netfilter_hook(void * priv, struct sk_buff * skb, const struct nf_hook_state * state)
{
    struct ethhdr * eth = NULL;
    eth = (struct ethhdr *)skb_mac_header(skb);
    pr_info("Source: %pM, Destination: %pM", eth->h_source, eth->h_dest);
    return NF_ACCEPT;
}

int __init initialize(void)
{
    pr_info("Initialized.");
    options.hook = netfilter_hook;
    options.pf = PF_INET;
    options.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&options);
    return 0;
}

void __exit uninitialize(void)
{
    nf_unregister_hook(&options);
    pr_info("Uninitialized.");
}

module_init(initialize);
module_exit(uninitialize);
