#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <string.h>
#include <linux/types.h>

#include <arpa/inet.h>

#include "config.h"

FILE *file;
#define FIELD_LENGTH 16

void set_config_defaults(struct f_config *cfg)
{
    cfg->updatetime = 0;
    for (__u16 i = 0; i < MAX_FILTERS; i++) { 
        cfg->filters[i].id = 0;
        cfg->filters[i].enabled = 0;
        cfg->filters[i].sip_start = 0;
        cfg->filters[i].sip_end = 0;
        cfg->filters[i].dip_start = 0;
        cfg->filters[i].dip_end = 0;
		cfg->filters[i].proto = -1;
    }
}


int open_config(const char *filename) {
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

int ip_read(config_setting_t *filter, char field[FIELD_LENGTH], char st_field[FIELD_LENGTH], 
                                                        char ed_field[FIELD_LENGTH], __u32 *start, __u32 *end) 
{
    const char *st, *ed, *def_ip;
    if (config_setting_lookup_string(filter, field, &def_ip)) {
        *start = htonl(inet_addr(def_ip));
        *end = htonl(inet_addr(def_ip));
        return 0;
    }    
    else if (config_setting_lookup_string(filter, st_field, &st) && config_setting_lookup_string(filter, ed_field, &ed)) {
        if (htonl(inet_addr(st)) > htonl(inet_addr(ed))) {
            fprintf(stderr, "IP range (%s -> %s) in filter invalid: start > end, skipping\n", st, ed);
        }
        else {
            *start = htonl(inet_addr(st));
            *end = htonl(inet_addr(ed));
            return 0;
        }
    }
    *start = 0;
    *end = 4294967295; //=UINT_MAX
    return 1;
}

int port_read(config_setting_t *filter, char field[FIELD_LENGTH], char st_field[FIELD_LENGTH], 
                                                        char ed_field[FIELD_LENGTH], __u16 *start, __u16 *end) {
    long long st, ed, port;
    if (config_setting_lookup_int64(filter, field, &port)) {
        *start = (__u16)port;
        *end = (__u16)port;
        return 0;
    }
    else if (config_setting_lookup_int64(filter, st_field, &st) && config_setting_lookup_int64(filter, ed_field, &ed)) {
        if (st > ed) {
            fprintf(stderr, "Port range (%hu -> %hu) in filter invalid: start > end, skipping\n", (__u16)st, (__u16)ed);
        }
        else {
            *start = (__u16)st;
            *end = (__u16)ed;
            return 0;
        }
    }
    *start = 0;
    *end = 65535;
    return 1;
}

int read_config(struct f_config *cfg)
{
    if (file == NULL) {
        return -1;
    }

    config_t conf;
    config_setting_t *setting;

    config_init(&conf);
    if (config_read(&conf, file) == CONFIG_FALSE) {
        fprintf(stderr, "Libconfig: file read error in line %d:  %s\n", config_error_line(&conf), config_error_text(&conf) );
        config_destroy(&conf);
        return 1;
    }

    setting = config_lookup(&conf, "filters");
    if (setting == NULL) {
        fprintf(stderr, "Libconfig: filters array not found\n");
        config_destroy(&conf);
        return 1;
    }

    int filters = 0;
    for (__u8 i = 0; i < config_setting_length(setting); i++) {
        config_setting_t* filter = config_setting_get_elem(setting, i);
        int enabled;

        if (config_setting_lookup_bool(filter, "enabled",  &enabled) == CONFIG_FALSE)
        {
            fprintf(stderr, "Libconfig: Correct 'enabled' parameter not found for filter %u\n", i);
            continue;
        }

        cfg->filters[i].enabled = enabled;
	
        ip_read(filter, "srcip", "sip_start", "sip_end", &(cfg->filters[i].sip_start), &(cfg->filters[i].sip_end));
        
        ip_read(filter, "dstip", "dip_start", "dip_end", &(cfg->filters[i].dip_start), &(cfg->filters[i].dip_end));

        const char *protocol;
        if (config_setting_lookup_string(filter, "proto", &protocol)) {
            if (strcmp(protocol, "tcp") == 0)	cfg->filters[i].proto = 6;
            else if (strcmp(protocol, "udp") == 0)	cfg->filters[i].proto = 17;
            else if (strcmp(protocol, "icmp") == 0)	cfg->filters[i].proto = 1;
        }
        
        port_read(filter, "sport", "sport_start", "sport_end", &(cfg->filters[i].sp_start), &(cfg->filters[i].sp_end));

        port_read(filter, "dport", "dport_start", "dport_end", &(cfg->filters[i].dp_start), &(cfg->filters[i].dp_end));

        cfg->filters[i].id = ++filters;
    }

    config_destroy(&conf);
    return 0;
}
