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
    for (__u16 i = 0; i < MAX_FILTERS; i++) { 
        cfg->filters[i].id = 0;
        cfg->filters[i].enabled = 0;
        cfg->filters[i].srcip = 0;
        cfg->filters[i].dstip = 0;
        cfg->filters[i].sip_start = 0;
        cfg->filters[i].sip_end = 0;
        cfg->filters[i].dip_start = 0;
        cfg->filters[i].dip_end = 0;
		cfg->filters[i].proto = -1;
		cfg->filters[i].do_sport = 0;
		cfg->filters[i].do_dport = 0;
		cfg->filters[i].do_sp_range = 0;
		cfg->filters[i].do_dp_range = 0;
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
        
        const char *sip;
        if (config_setting_lookup_string(filter, "srcip", &sip)) {
            cfg->filters[i].srcip = inet_addr(sip);
        }
        
        const char *dip;
        if (config_setting_lookup_string(filter, "dstip", &dip)) {
            cfg->filters[i].dstip = inet_addr(dip);
        }
	
        //IP RANGES
        const char *sip_st;
        const char *sip_ed;
        if (config_setting_lookup_string(filter, "sip_start", &sip_st) && config_setting_lookup_string(filter, "sip_end", &sip_ed)) {
            if (htonl(inet_addr(sip_st)) > htonl(inet_addr(sip_ed))) {
        		fprintf(stderr, "Source IP range in filter %u invalid: start > end, skipping\n", i);
        	}
        	else {
		        cfg->filters[i].sip_start = inet_addr(sip_st);
		        cfg->filters[i].sip_end = inet_addr(sip_ed);
		    }
        }
        
        const char *dip_st;
        const char *dip_ed;
        if (config_setting_lookup_string(filter, "dip_start", &dip_st) && config_setting_lookup_string(filter, "dip_end", &dip_ed)) {
            if (htonl(inet_addr(dip_st)) > htonl(inet_addr(dip_ed))) {
        		fprintf(stderr, "Destination IP range in filter %u invalid: start > end, skipping\n", i);
        	}
        	else {
		        cfg->filters[i].dip_start = inet_addr(dip_st);
		        cfg->filters[i].dip_end = inet_addr(dip_ed);
		    }
        }
        // ==========

        const char *prt;
        if (config_setting_lookup_string(filter, "proto", &prt)) {
            if (strcmp(prt, "tcp") == 0)	cfg->filters[i].proto = 6;
            else if (strcmp(prt, "udp") == 0)	cfg->filters[i].proto = 17;
            else if (strcmp(prt, "icmp") == 0)	cfg->filters[i].proto = 1;
        }

        long long tcpsport;
        if (config_setting_lookup_int64(filter, "sport", &tcpsport)) {
            cfg->filters[i].sport = (__u16)tcpsport;
            cfg->filters[i].do_sport = 1;
        }

        long long tcpdport;
        if (config_setting_lookup_int64(filter, "dport", &tcpdport)) {
            cfg->filters[i].dport = (__u16)tcpdport;
            cfg->filters[i].do_dport = 1;
        }
        
        //PORT RANGES
        long long sp_st, sp_ed;
        if (config_setting_lookup_int64(filter, "sport_start", &sp_st) && config_setting_lookup_int64(filter, "sport_end", &sp_ed)) {
        	if (sp_st > sp_ed) {
        		fprintf(stderr, "Source port range in filter %u invalid: start > end, skipping\n", i);
        	}
        	else {
	            cfg->filters[i].sp_start = (__u16)sp_st;
		        cfg->filters[i].sp_end = (__u16)sp_ed;
		        cfg->filters[i].do_sp_range = 1;
        	}
        }

        long long dp_st, dp_ed;
        if (config_setting_lookup_int64(filter, "dport_start", &dp_st) && config_setting_lookup_int64(filter, "dport_end", &dp_ed)) {
        	if (dp_st > dp_ed) {
        		fprintf(stderr, "Source port range in filter %u invalid: start > end, skipping\n", i);
        	}
        	else {
	            cfg->filters[i].dp_start = (__u16)dp_st;
		        cfg->filters[i].dp_end = (__u16)dp_ed;
		        cfg->filters[i].do_dp_range = 1;
        	}
        }

        //===========

        cfg->filters[i].id = ++filters;
    }

    config_destroy(&conf);
    return 0;
}
