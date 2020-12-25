#include <linux/bpf.h>
#include <bpf_helpers.h>

#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

#include "xdp_prog.h"
#include "xdpfwd.h"

struct bpf_map_def SEC("maps") forward_map =
{
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct forward_key),
    .value_size = sizeof(struct forward_info),
    .max_entries = 2048

};

struct bpf_map_def SEC("maps") forward_maps =
{
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 8096
};

int forward_packet(struct forward_key *key, struct ethhdr *eth, struct iphdr *iph)
{

    return XDP_PASS;
}

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{


    return XDP_PASS;
}