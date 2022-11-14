#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <bpf/bpf_helpers.h>

#include "xdp_prog.h"

struct bpf_map_def SEC("maps") filters_map =
{
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(struct filter),
        .max_entries = MAX_FILTERS
};

struct bpf_map_def SEC("maps") stats_map =
{
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(struct stats),
        .max_entries = 1
};

static __always_inline int range_check(__u32 var, __u32 start, __u32 end) {
    if ((var < start) || (var > end)) {
        return 1;
    }
    return 0;
}

static __always_inline int ip_check(__u32 ip, __u32 packet_ip, __u32 start, __u32 end) {
    if (ip != 0 && packet_ip != ip) {
        return 1;
    }
    if (start != 0 && end != 0 && range_check(packet_ip, start, end)) {
        return 1;
    }
    return 0;
}


SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end) {
        return XDP_PASS;
    }

    if (unlikely(eth->h_proto != htons(ETH_P_IP))) {
        return XDP_PASS;
    }

    struct iphdr *iph = NULL;
    iph = (data + sizeof(struct ethhdr));

    if (unlikely(iph + 1 > (struct iphdr *)data_end)) {
        return XDP_PASS;
    }

    if ((iph && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP)) {
        return XDP_PASS;
    }
    __u32 key = 0;
    struct stats *stats = bpf_map_lookup_elem(&stats_map, &key);

    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;

    switch (iph->protocol) {
        case IPPROTO_TCP:
            tcph = ((void*)iph + (iph->ihl * 4));
            if (tcph + 1 > (struct tcphdr *)data_end) {
                tcph = NULL;
            }
            break;

        case IPPROTO_UDP:
            udph = ((void*)iph + (iph->ihl * 4));
            if (udph + 1 > (struct udphdr *)data_end) {
                udph = NULL;
            }
            break;

        case IPPROTO_ICMP:
            icmph = ((void*)iph + (iph->ihl * 4));
            if (icmph + 1 > (struct icmphdr *)data_end) {
                icmph = NULL;
            }
            break;
    }

    for (__u8 i = 0; i < MAX_FILTERS; i++)
    {
        __u32 key = i;
        struct filter *filter = bpf_map_lookup_elem(&filters_map, &key);
        if (!filter || filter->id < 1) {
            break;
        }
        if (!filter->enabled) {
            continue;
        }

        if ( ip_check(filter->srcip, htonl(iph->saddr), filter->sip_start, filter->sip_end) ) {
            continue;
        }

        if ( ip_check(filter->dstip, htonl(iph->daddr), filter->dip_start, filter->dip_end) ) {
            continue;
        }
        
        if (filter->proto == 6) //TCP
        {
            if (!tcph) {
                continue;
            }
            if (range_check(htons(tcph->source), filter->sp_start, filter->sp_end)) {
                continue;
            }
            if (range_check(htons(tcph->dest), filter->dp_start, filter->dp_end)) {
                continue;
            }
        }
        else if (filter->proto == 17) { //UDP
            if (!udph) {
                continue;
            }
            if (range_check(htons(udph->source), filter->sp_start, filter->sp_end)) {
                continue;
            }
            if (range_check(htons(udph->dest), filter->dp_start, filter->dp_end)) {
                continue;
            }
        }
        else if (filter->proto == 1) { //ICMP
            if (!icmph) {
                continue;
            }
        }

        goto matched;
    }

    return XDP_PASS;

    matched:
        if (stats) {
            stats->dropped++;
        }

        return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
