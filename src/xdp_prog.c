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

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end) {
        return XDP_DROP;
    }

    if (unlikely(eth->h_proto != htons(ETH_P_IP))) {
        return XDP_PASS;
    }
    
    struct iphdr *iph = NULL;
    iph = (data + sizeof(struct ethhdr));

    if (unlikely(iph + 1 > (struct iphdr *)data_end)) {
        return XDP_DROP;
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
	tcph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));
	if (tcph + 1 > (struct tcphdr *)data_end) {
	    return XDP_DROP;
	}
	break;

    case IPPROTO_UDP:
	udph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));
	if (udph + 1 > (struct udphdr *)data_end) {
	    return XDP_DROP;
	}
	break;

    case IPPROTO_ICMP:
	icmph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));
	if (icmph + 1 > (struct icmphdr *)data_end) {
	    return XDP_DROP;
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
        
        if (!filter->enabled)
        {
            continue;
        }
        
		if (filter->srcip != 0 && iph->saddr != filter->srcip)
		{
			continue;
		}
		if (filter->dstip != 0 && iph->daddr != filter->dstip)
		{
			continue;
		}
		if ( filter->sip_start != 0 && filter->sip_end !=0 && ( ( htonl(iph->saddr) < htonl(filter->sip_start) ) || ( htonl(iph->saddr) > htonl(filter->sip_end) ) ) ) {
			continue;
		}
		if ( filter->dip_start != 0 && filter->dip_end !=0 && ( ( htonl(iph->saddr) < htonl(filter->dip_start)) || ( htonl(iph->saddr) > htonl(filter->dip_end) ) ) ) {
			continue;
		}	
		
        if (filter->proto == 6) {
            if (!tcph) {
                continue;
            }
            if (filter->do_sport && htons(filter->sport) != tcph->source) {
                continue;
            }
            if (filter->do_dport && htons(filter->dport) != tcph->dest) {
                continue;
            }
            if (filter->do_sp_range && ((htons(tcph->source) < filter->sp_start) || (htons(tcph->source) > filter->sp_end))) {
            	continue;
            }
            if (filter->do_dp_range && ((htons(tcph->source) < filter->dp_start) || (htons(tcph->source) > filter->dp_end))) {
            	continue;
            }
        }
        else if (filter->proto == 17) {
            if (!udph) {
                continue;
            }
            if (filter->do_sport && htons(filter->sport) != udph->source) {
                continue;
            }
            if (filter->do_dport && htons(filter->dport) != udph->dest) {
                continue;
            }
			if ( filter->do_sp_range && ( (htons(udph->source) < filter->sp_start) || (htons(udph->source) > filter->sp_end) ) ) {
            	continue;
            }
            if ( filter->do_dp_range && ( (htons(udph->source) < filter->dp_start) || (htons(udph->source) > filter->dp_end) ) ) {
            	continue;
            }
        }
        else if (filter->proto == 1)
        {
            if (!icmph)
            {
                continue;
            }
        }

        goto matched;
    }
            
    return XDP_PASS;

    matched:
            if (stats)
            {
                stats->dropped++;
            }

            return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
