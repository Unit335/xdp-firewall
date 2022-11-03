#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <string.h>
#include <linux/types.h>

#include <arpa/inet.h>

#include "config.h"

FILE *file;

void setcfgdefaults(struct f_config *cfg)
{
    cfg->updatetime = 0;
    cfg->interface = "eth0";

    for (__u16 i = 0; i < MAX_FILTERS; i++) {
        cfg->filters[i].id = 0;
        cfg->filters[i].enabled = 0;
        cfg->filters[i].srcip = 0;
        cfg->filters[i].dstip = 0;

        
        cfg->filters[i].tcpopts.enabled = 0;
        cfg->filters[i].tcpopts.do_dport = 0;
        cfg->filters[i].tcpopts.do_dport = 0;

        cfg->filters[i].udpopts.enabled = 0;
        cfg->filters[i].udpopts.do_sport = 0;
        cfg->filters[i].udpopts.do_dport = 0;

        cfg->filters[i].icmpopts.enabled = 0;
    }
}


int opencfg(const char *filename) {
    if (file != NULL) {
        fclose(file);

        file = NULL;
    }
    file = fopen(filename, "r");
    if (file == NULL) {
        return 1;
    }
    return 0;
}

int readcfg(struct f_config *cfg)
{
    if (file == NULL) {
        return -1;
    }

    config_t conf;
    config_setting_t *setting;

    config_init(&conf);
    if (config_read(&conf, file) == CONFIG_FALSE) {
        perror("Libconfig: file read error\n");
        config_destroy(&conf);
        return 1;
    }

    setting = config_lookup(&conf, "filters");
    if (setting == NULL) {
        perror("Libconfig: filters array reading error\n");
        config_destroy(&conf);
        return 1;
    }

    int filters = 0;
    for (__u8 i = 0; i < config_setting_length(setting); i++) {
        config_setting_t* filter = config_setting_get_elem(setting, i);
        int enabled;

        if (config_setting_lookup_bool(filter, "enabled",  &enabled) == CONFIG_FALSE)
        {
            perror("Libconfig: 'enabled' read erro\n");
            continue;
        }

        cfg->filters[i].enabled = enabled;
        const char *sip;
        if (config_setting_lookup_string(filter, "srcip", &sip)) {
            cfg->filters[i].srcip = inet_addr(sip);
        }

        const char *dip;
        if (config_setting_lookup_string(filter, "dstip", &dip)) {
            cfg->filters[i].dstip = inet_addr(dip);
        }

        // TCP
        int tcpenabled;
        if (config_setting_lookup_bool(filter, "tcp_enabled", &tcpenabled)) {
            cfg->filters[i].tcpopts.enabled = tcpenabled;
        }

        long long tcpsport;
        if (config_setting_lookup_int64(filter, "tcp_sport", &tcpsport)) {
            cfg->filters[i].tcpopts.sport = (__u16)tcpsport;
            cfg->filters[i].tcpopts.do_sport = 1;
        }

        long long tcpdport;
        if (config_setting_lookup_int64(filter, "tcp_dport", &tcpdport)) {
            cfg->filters[i].tcpopts.dport = (__u16)tcpdport;
            cfg->filters[i].tcpopts.do_dport = 1;
        }

        int udpenabled;
        if (config_setting_lookup_bool(filter, "udp_enabled", &udpenabled)) {
            cfg->filters[i].udpopts.enabled = udpenabled;
        }

        long long udpsport;
        if (config_setting_lookup_int64(filter, "udp_sport", &udpsport)) {
            cfg->filters[i].udpopts.sport = (__u16)udpsport;
            cfg->filters[i].udpopts.do_sport = 1;
        }

        long long udpdport;
        if (config_setting_lookup_int64(filter, "udp_dport", &udpdport)) {
            cfg->filters[i].udpopts.dport = (__u16)udpdport;
            cfg->filters[i].udpopts.do_dport = 1;
        }

        // ICMP
        int icmpenabled;
        if (config_setting_lookup_bool(filter, "icmp_enabled", &icmpenabled)) {
            cfg->filters[i].icmpopts.enabled = icmpenabled;
        }

        cfg->filters[i].id = ++filters;
    }

    config_destroy(&conf);
    return 0;
}
