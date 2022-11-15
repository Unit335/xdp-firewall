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

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end;
    void *data_start = (void *)(long)ctx->data;

    struct ethhdr *eth = data_start;
    if (eth + 1 > (struct ethhdr *)data_end) {
        return XDP_PASS;
    }

    if (unlikely(eth->h_proto != htons(ETH_P_IP))) {
        return XDP_PASS;
    }

    struct iphdr *ip_header = NULL;
    ip_header = (data_start + sizeof(struct ethhdr));

    if (unlikely(ip_header + 1 > (struct iphdr *)data_end)) {
        return XDP_PASS;
    }

    if ((ip_header && ip_header->protocol != IPPROTO_UDP && ip_header->protocol != IPPROTO_TCP && ip_header->protocol != IPPROTO_ICMP)) {
        return XDP_PASS;
    }
    __u32 key = 0;
    struct stats *stats = bpf_map_lookup_elem(&stats_map, &key);

    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;
    struct icmphdr *icmp_header = NULL;

    switch (ip_header->protocol) {
        case IPPROTO_TCP:
            tcp_header = ((void*)ip_header + (ip_header->ihl * 4));
            if (tcp_header + 1 > (struct tcphdr *)data_end) {
                tcp_header = NULL;
            }
            break;

        case IPPROTO_UDP:
            udp_header = ((void*)ip_header + (ip_header->ihl * 4));
            if (udp_header + 1 > (struct udphdr *)data_end) {
                udp_header = NULL;
            }
            break;

        case IPPROTO_ICMP:
            icmp_header = ((void*)ip_header + (ip_header->ihl * 4));
            if (icmp_header + 1 > (struct icmphdr *)data_end) {
                icmp_header = NULL;
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

        if (range_check(htonl(ip_header->saddr), filter->sip_start, filter->sip_end)) {
            continue;
        }
        if (range_check(htonl(ip_header->daddr), filter->dip_start, filter->dip_end)) {
            continue;
        }

        if (filter->proto == 6) //TCP
        {
            if (!tcp_header) {
                continue;
            }
            if (range_check(htons(tcp_header->source), filter->sp_start, filter->sp_end)) {
                continue;
            }
            if (range_check(htons(tcp_header->dest), filter->dp_start, filter->dp_end)) {
                continue;
            }
        }
        else if (filter->proto == 17) { //UDP
            if (!udp_header) {
                continue;
            }
            if (range_check(htons(udp_header->source), filter->sp_start, filter->sp_end)) {
                continue;
            }
            if (range_check(htons(udp_header->dest), filter->dp_start, filter->dp_end)) {
                continue;
            }
        }
        else if (filter->proto == 1) { //ICMP
            if (!icmp_header) {
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
