#pragma once

#include <linux/types.h>

#define MAX_PCKT_LENGTH 65535
#define MAX_FILTERS 100
#define MAX_TRACK_IPS 100000
#define MAX_CPUS 256
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define unlikely(x) __builtin_expect(!!(x), 0)

struct tcpopts
{
    unsigned int enabled : 1;
    unsigned int do_sport : 1;
    __u16 sport;
    unsigned int do_dport : 1;
    __u16 dport;

};

struct udpopts
{
    unsigned int enabled : 1;
    unsigned int do_sport : 1;
    __u16 sport;
    unsigned int do_dport : 1;
    __u16 dport;
};

struct icmpopts
{
    unsigned int enabled : 1;
};

struct filter
{
    __u8 id;
    unsigned int enabled : 1;
    __u32 srcip;
    __u32 dstip;
    struct tcpopts tcpopts;
    struct udpopts udpopts;
    struct icmpopts icmpopts;
};

struct stats
{
    __u64 allowed;
    __u64 dropped;
};


