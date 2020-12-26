#include <linux/bpf.h>
#include <bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

#include <inttypes.h>

#include "xdp_prog.h"
#include "xdpfwd.h"

struct bpf_map_def SEC("maps") forward_map =
{
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct forward_key),
    .value_size = sizeof(struct forward_info),
    .max_entries = MAXRULES
};

struct bpf_map_def SEC("maps") tcp_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct port_key),
    .value_size = sizeof(struct connection),
    .max_entries = (MAXRULES * MAXPORTS)
};

struct bpf_map_def SEC("maps") udp_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct port_key),
    .value_size = sizeof(struct connection),
    .max_entries = (MAXRULES * MAXPORTS)
};

struct bpf_map_def SEC("maps") connection_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct conn_key),
    .value_size = sizeof(struct connection),
    .max_entries = MAXCONNECTIONS
};

int forward_packet(struct forward_info *info, struct ethhdr *eth, struct iphdr *iph)
{

    return XDP_PASS;
}

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize packet information.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Initialize Ethernet header.
    struct ethhdr *eth = data;

    // Check Ethernet header.
    if (eth + 1 > (struct ethhdr *)data_end)
    {
        return XDP_DROP;
    }

    // If not IPv4, pass down network stack. Will be adding IPv6 support later on.
    if (eth->h_proto != htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    // Initialize IP header.
    struct iphdr *iph = data + sizeof(struct ethhdr);

    // Check IP header.
    if (iph + 1 > (struct iphdr *)data_end)
    {
        return XDP_DROP;
    }

    // We only support TCP, UDP, and ICMP for forwarding at this moment.
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_ICMP)
    {
        return XDP_PASS;
    }

    // Get layer-4 protocol information.
    struct udphdr *udph = NULL;
    struct tcphdr *tcph = NULL;

    uint16_t portkey = 0;

    switch (iph->protocol)
    {
        case IPPROTO_TCP:
            tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (tcph + 1 > (struct tcphdr *)data_end)
            {
                return XDP_DROP;
            }

            break;

        case IPPROTO_UDP:
            udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

            if (udph + 1 > (struct udphdr *)data_end)
            {
                return XDP_DROP;
            }

            break;
    }

    if (udph)
    {
        portkey = htons(udph->dest);
    }
    else if (tcph)
    {
        portkey = htons(tcph->dest);
    }

    // Construct forward key.
    struct forward_key fwdkey = {0};
    
    fwdkey.bindaddr = iph->saddr;
    fwdkey.protocol = iph->protocol;
    fwdkey.bindport = portkey;
    
    struct forward_info *fwdinfo = bpf_map_lookup_elem(&forward_map, &fwdkey);

    if (fwdinfo)
    {
        // Check if we have an existing connection for this address.
        struct conn_key connkey = {0};

        connkey.clientaddr = iph->saddr;
        connkey.bindaddr = iph->daddr;
        connkey.protocol = iph->protocol;

        struct connection *conn = bpf_map_lookup_elem(&connection_map, &connkey);

        if (conn)
        {

        }
    }
    else
    {
        // Look for packets coming back from bind addresses.
        fwdkey.bindaddr = iph->saddr;
        fwdkey.protocol = iph->protocol;

        if (udph)
        {
            portkey = htons(udph->source);
        }
        else if (tcph)
        {
            portkey = htons(tcph->source);
        }

        fwdkey.bindport = portkey;

        fwdinfo = bpf_map_lookup_elem(&forward_map, &fwdkey);

        if (fwdinfo)
        {
            // Now deal with packets coming back.
        }
    }

    return XDP_PASS;
}