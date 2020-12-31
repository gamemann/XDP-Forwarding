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

#include "csum.h"

//#define DEBUG

#ifdef DEBUG

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

#endif

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

static __always_inline void swapeth(struct ethhdr *eth)
{
    uint8_t tmp[ETH_ALEN];

    memcpy(&tmp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, &tmp, ETH_ALEN);
}

static __always_inline int forwardpacket4(struct forward_info *info, struct connection *conn, struct ethhdr *eth, struct iphdr *iph, void *data, void *data_end)
{
    // Swap ethernet source and destination MAC addresses.
    swapeth(eth);

    // Swap IP addresses.
    uint32_t oldsrcaddr = iph->saddr;
    uint32_t olddestaddr = iph->daddr;

    iph->saddr = iph->daddr;

    if (info)
    {
        iph->daddr = info->destaddr;
    }
    else
    {
        iph->daddr = conn->clientaddr;
    }
    
    // Handle protocol.
    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

        // Check header.
        if (tcph + 1 > (struct tcphdr *)data_end)
        {
            return XDP_DROP;
        }

        // Handle ports.
        uint16_t oldsrcport = tcph->source;
        uint16_t olddestport = tcph->dest;

        if (info)
        {
            tcph->source = conn->port;
            tcph->dest = info->destport;
        }
        else
        {
            tcph->source = conn->bindport;
            tcph->dest = conn->clientport;
        }
        
        // Recalculate checksum.
        tcph->check = csum_diff4(olddestaddr, iph->daddr, tcph->check);
        tcph->check = csum_diff4(oldsrcaddr, iph->saddr, tcph->check);

        tcph->check = csum_diff4(oldsrcport, tcph->source, tcph->check);
        tcph->check = csum_diff4(olddestport, tcph->dest, tcph->check);
        
        #ifdef DEBUG
            bpf_printk("Forward Port => %" PRIu16 ":%" PRIu16 ".\n", ntohs(tcph->source), ntohs(tcph->dest));
        #endif
    }
    else if (iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

        // Check header.
        if (udph + 1 > (struct udphdr *)data_end)
        {
            return XDP_DROP;
        }

        // Handle ports.
        uint16_t oldsrcport = udph->source;
        uint16_t olddestport = udph->dest;

        if (info)
        {
            udph->source = conn->port;
            udph->dest = info->destport;
        }
        else
        {
            udph->source = conn->bindport;
            udph->dest = conn->clientport;
        }

        // Recalculate checksum.
        udph->check = csum_diff4(olddestaddr, iph->daddr, udph->check);
        udph->check = csum_diff4(oldsrcaddr, iph->saddr, udph->check);

        udph->check = csum_diff4(oldsrcport, udph->source, udph->check);
        udph->check = csum_diff4(olddestport, udph->dest, udph->check);

        #ifdef DEBUG
            bpf_printk("Forward Port => %" PRIu16 ":%" PRIu16 ".\n", ntohs(udph->source), ntohs(udph->dest));
        #endif
    }

    // Recalculate IP checksum and send packet back out TX path.
    update_iph_checksum(iph);

    #ifdef DEBUG
        bpf_printk("Forward IP => %" PRIu32 ":%" PRIu32 " (%" PRIu8")\n", iph->saddr, iph->daddr, iph->protocol);
    #endif

    return XDP_TX;
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
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
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
    if (unlikely(iph + 1 > (struct iphdr *)data_end))
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

    portkey = (tcph) ? tcph->source : (udph) ? udph->source : 0;

    // Construct forward key.
    struct forward_key fwdkey = {0};
    
    fwdkey.bindaddr = iph->daddr;
    fwdkey.protocol = iph->protocol;
    fwdkey.bindport = portkey;
    
    struct forward_info *fwdinfo = bpf_map_lookup_elem(&forward_map, &fwdkey);

    if (fwdinfo)
    {
        #ifdef DEBUG
            bpf_printk("Matched forward rule %" PRIu32 ":%" PRIu16 " (%" PRIu8 ").\n", fwdkey.bindaddr, fwdkey.bindport, fwdkey.protocol);
        #endif

        uint64_t now = bpf_ktime_get_ns();

        // Check if we have an existing connection for this address.
        struct conn_key connkey = {0};

        connkey.clientaddr = iph->saddr;
        connkey.clientport = (tcph) ? tcph->source : (udph) ? udph->source : 0;
        connkey.bindaddr = iph->daddr;
        connkey.bindport = portkey;
        connkey.protocol = iph->protocol;

        struct connection *conn = bpf_map_lookup_elem(&connection_map, &connkey);

        if (conn)
        {
            // Update some things before forwarding packet.
            conn->lastseen = now;
            conn->count++;

            #ifdef DEBUG
                bpf_printk("Forwarding packet from existing connection. %" PRIu32 " with count %" PRIu64 "\n", iph->saddr, conn->count);
            #endif
            
            // Forward the packet!
            return forwardpacket4(fwdinfo, conn, eth, iph, data, data_end);
        }

        #ifdef DEBUG
            bpf_printk("Inserting new connection for %" PRIu32 "\n", iph->saddr);
        #endif
        
        // We don't have an existing connection, we must find one.
        struct bpf_map_def *map = (tcph) ? &tcp_map : (udph) ? &udp_map : NULL;

        if (map)
        {
            uint16_t porttouse = 0;
            uint64_t last = UINT64_MAX;

            // Things to save about new connection.
            uint32_t caddr = 0;
            uint16_t cport = 0;

            for (uint16_t i = 1; i <= MAXPORTS; i++)
            {
                struct port_key pkey = {0};
                pkey.bindaddr = iph->daddr;
                pkey.port = htons(i);

                struct connection *newconn = bpf_map_lookup_elem(map, &pkey);

                if (!newconn)
                {
                    porttouse = i;
                    last = 0;

                    break;
                }
                else
                {
                    // We'll want to replace the most inactive connection.
                    if (last > newconn->lastseen)
                    {
                        porttouse = i;
                        last = newconn->lastseen;
                        caddr = newconn->clientaddr;
                        cport = newconn->clientport;
                    }
                }
            }

            #ifdef DEBUG
                bpf_printk("Decided to use port %" PRIu16 "\n", porttouse);
            #endif

            if (porttouse > 0)
            {
                // If last is higher than 0, we're replacing an existing connection. Remove that connection from map.
                if (last > 0)
                {
                    struct conn_key oconnkey = {0};
                    oconnkey.bindaddr = iph->daddr;
                    oconnkey.bindport = portkey;
                    oconnkey.protocol = iph->protocol;
                    oconnkey.clientaddr = caddr;
                    oconnkey.clientport = cport;

                    bpf_map_delete_elem(&connection_map, &oconnkey);
                }

                // Insert new connection.
                struct conn_key nconnkey = {0};
                nconnkey.bindaddr = iph->daddr;
                nconnkey.bindport = portkey;
                nconnkey.clientaddr = iph->saddr;
                nconnkey.clientport = (tcph) ? tcph->source : (udph) ? udph->source : 0;
                nconnkey.protocol = iph->protocol;

                struct connection newconn = {0};
                newconn.clientaddr = iph->saddr;
                newconn.clientport = (tcph) ? tcph->source : (udph) ? udph->source : 0;
                newconn.lastseen = now;
                newconn.count = 1;
                newconn.bindport = portkey;
                newconn.port = htons(porttouse);

                bpf_map_update_elem(&connection_map, &nconnkey, &newconn, BPF_ANY);

                // Insert into port map.
                struct port_key npkey = {0};
                npkey.bindaddr = iph->daddr;
                npkey.port = htons(porttouse);

                bpf_map_update_elem(map, &npkey, &newconn, BPF_ANY);

                #ifdef DEBUG
                    bpf_printk("Forwarding packet from new connection for %" PRIu32 "\n", iph->saddr);
                #endif

                // Finally, forward packet.
                return forwardpacket4(fwdinfo, &newconn, eth, iph, data, data_end);
            }
        }
    }
    else
    {
        // Look for packets coming back from bind addresses.
        portkey = (tcph) ? tcph->source : (udph) ? udph->source : 0;

        struct port_key pkey = {0};
        pkey.bindaddr = iph->daddr;
        pkey.port = portkey;

        // Find out what the client IP is.
        struct connection *conn = NULL;

        if (tcph)
        {
            conn = bpf_map_lookup_elem(&tcp_map, &pkey);
        }
        else if (udph)
        {
            conn = bpf_map_lookup_elem(&udp_map, &pkey);
        }

        if (conn)
        {
            #ifdef DEBUG
                bpf_printk("Found connection on %" PRIu16 ". Forwarding back to %" PRIu32 ":%" PRIu16 "\n", ntohs(pkey.port), conn->clientaddr, conn->clientport);
            #endif

            // Now forward packet back to actual client.
            return forwardpacket4(NULL, conn, eth, iph, data, data_end);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";