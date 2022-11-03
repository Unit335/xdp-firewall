#pragma once

#include <linux/types.h>
#define MAX_FILTERS 100

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
struct f_config
{
    char *interface;
    __u16 updatetime;
    struct filter filters[MAX_FILTERS];
};

void setcfgdefaults(struct f_config *cfg);
int opencfg(const char *filename);
int readcfg(struct f_config *cfg);
