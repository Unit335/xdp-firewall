#pragma once

#include <linux/types.h>

#define MAX_PCKT_LENGTH 65535
#define MAX_FILTERS 100
#define MAX_TRACK_IPS 100000
#define MAX_CPUS 256
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#endif
#define unlikely(x) __builtin_expect(!!(x), 0)

struct filter
{
    __u8 id;

    unsigned int enabled : 1;

    __u32 sip_start;
    __u32 sip_end; 
    __u32 dip_start;
    __u32 dip_end; 

    short int proto;

    __u16 sp_start, sp_end;
    __u16 dp_start, dp_end;


};
struct stats
{
    __u64 allowed;
    __u64 dropped;
};


