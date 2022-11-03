#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <sys/sysinfo.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>

#include "../common//bfp-xdp.h"
#include "bpf_util.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *usage_msg = "Usage: ./xb-stats [options] \n\n -h, --help \t\tdisplays help\n -d, --device\t\tdevice from which to read stats\n";

struct stats_conf
{
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
};

struct stats
{
	__u64 allowed;
	__u64 dropped;
};

const char *pin_basedir = "/sys/fs/bpf";

int parse_cmdline(int argc, char *argv[], struct stats_conf *cfg)
{
	if (argc < 3) {
		return 1;
	}
	if (argc != 0)
	{
		const char *short_options = "hd:";
		const struct option long_options[] = {
			{"help", no_argument, NULL, 'h'},
			{"device", required_argument, NULL, 'd'},
			{NULL, 0, NULL, 0}};
		int rez;
		while ((rez = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
			switch (rez)
			{
			case 'h':
				return 1;
				break;
			case 'd':
				if (strlen(optarg) >= IF_NAMESIZE) {
					perror("Devce name too long\n");
					return 1;
				}
				cfg->ifname = (char *)&cfg->ifname_buf;
				strncpy(cfg->ifname, optarg, IF_NAMESIZE);
				cfg->ifindex = if_nametoindex(cfg->ifname);
				if (cfg->ifindex == 0) {
					perror("Device index error\n");
					return 1;
				}
				break;
			default:
				printf("%s\n", usage_msg);
				return 1;
				break;
			}
		}
	}
	return 0;
}
int main(int argc, char **argv)
{
	struct bpf_map_info info = {0};
	char pin_dir[PATH_MAX];
	int stats_map_fd;
	int len;

	struct stats_conf cfg = {
		.ifindex = -1,
	};
	if (parse_cmdline(argc, argv, &cfg) > 0) {
		printf("%s\n", usage_msg);
		return 0;
	}

	if (cfg.ifindex == -1) {
		perror("No valid device specified\n");
		printf("%s\n", usage_msg);
		return 1;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		perror("Error while creating pin dirname\n");
		return 1;
	}

	stats_map_fd = open_bpf_map_file(pin_dir, "stats_map", &info);
	if (stats_map_fd < 0) {
		return 1;
	}

	time_t statslastupdated = time(NULL);
	time_t current_time;

	int cpus = get_nprocs_conf();
	int max_cpus = 2;
	while (1) {
		current_time = time(NULL);

		if ((current_time - statslastupdated) > 2) {
			__u32 key = 0;
			struct stats stats[max_cpus];
			__u64 dropped = 0;
			if (bpf_map_lookup_elem(stats_map_fd, &key, stats) != 0) {
				perror("Stats lookup error\n");
				continue;
			}

			for (int i = 0; i < cpus; i++) {
				dropped += stats[i].dropped;
			}
			fprintf(stdout, "\rPackets Dropped: %llu", dropped);
		}
	}

	return 0;
}
