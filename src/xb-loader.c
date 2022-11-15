#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h>
#include <libconfig.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/if_xdp.h>

#include "../common/defines.h"
#include "../common/config.h"
#include "../common/bfp-xdp.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char *default_filename = "xdp_prog.o";
const char *usage_msg = "Usage: ./xb-loader [options]\n\nRequired options:\n -d, --dev <interface>      Operate on interface <interface>\n\nOther options:\n\n -h, --help                 Displays help\n -S, --skb-mode             SKB/generic mode\n -N, --native-mode          native mode \n -F, --force                replaces existing program on interface\n -U, --unload               Unload existing program\n -W, --update-filters       Updates filters based on xdp.conf \n\n";
const char *filters_file = "xdp.conf";
const char *pin_basedir = "/sys/fs/bpf";
const char *map_name = "stats_map";
const char *map_name_filters = "filters_map";

int parse_cmdline(int argc, char *argv[], struct config *cfg)
{
	char *dest;
	if (argc < 2) {
		return 1;
	}

	if (argc != 0) {
		const char *short_options = "hd:SNFUWf:";
		const struct option long_options[] = {
			{"help", no_argument, NULL, 'h'},
			{"device", required_argument, NULL, 'd'},
			{"skb-mode", no_argument, NULL, 'S'},
			{"native-mode", no_argument, NULL, 'N'},
			{"force", no_argument, NULL, 'F'},
			{"unload", no_argument, NULL, 'U'},
			{"filename", no_argument, NULL, 'f'},
			{"update-filters", no_argument, NULL, 'W'},
			{NULL, 0, NULL, 0}};
		int rez;
		while ((rez = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
		{
			switch (rez)
			{
			case 'h':
				return 1;
			case 'd':
				if (strlen(optarg) >= IF_NAMESIZE)
				{
					perror("Interface name too long\n");
					return 1;
				}
				cfg->ifname = (char *)&cfg->ifname_buf;
				strncpy(cfg->ifname, optarg, IF_NAMESIZE);
				cfg->ifindex = if_nametoindex(cfg->ifname);
				if (cfg->ifindex == 0)
				{
					perror("Wrong interface index\n");
					return 1;
				}
				break;
			case 'S':
				cfg->xdp_flags &= ~XDP_FLAGS_MODES;	  /* Clear flags */
				cfg->xdp_flags |= XDP_FLAGS_SKB_MODE; /* Set   flag */
				cfg->xsk_bind_flags &= XDP_ZEROCOPY;
				cfg->xsk_bind_flags |= XDP_COPY;
				break;
			case 'N':
				cfg->xdp_flags &= ~XDP_FLAGS_MODES;	  /* Clear flags */
				cfg->xdp_flags |= XDP_FLAGS_DRV_MODE; /* Set   flag */
				break;
			case 'F':
				cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
				break;
			case 'U':
				cfg->do_unload = true;
				break;
			case 'f':
				dest = (char *)&cfg->filename;
				strncpy(dest, optarg, sizeof(cfg->filename));
				break;
			case 'W':
				cfg->do_filters_update = true;
				break;
			default:
				return 1;
			}
		}
	}
	return 0;
}

int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, const char *subdir)
{
	char map_filename[PATH_MAX];
	char pin_dir[PATH_MAX];
	int err, len;

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
	if (len < 0) {
		perror("Creating dir for pinning maps error\n");
		return 1;
	}
	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
				   pin_basedir, subdir, map_name);
	if (len < 0) {
		perror("Map name creation error\n");
		return 1;
	}

	if (access(map_filename, F_OK) != -1) {
		printf(" == Unpinning maps in %s/\n", pin_dir);
		err = bpf_object__unpin_maps(bpf_obj, pin_dir);
		if (err) {
			perror("Unpinning maps error\n");
			return 1;
		}
	}

	printf(" == Pinning maps in %s/\n", pin_dir);
	err = bpf_object__pin_maps(bpf_obj, pin_dir);
	if (err)
		return 1;

	return 0;
}

void update_filters(struct f_config *cfg, int filtersmap)
{
	for (__u8 i = 0; i < MAX_FILTERS; i++) {
		__u32 key = i;
		bpf_map_delete_elem(filtersmap, &key);
	}

	for (__u32 i = 0; i < MAX_FILTERS; i++) {
		if (cfg->filters[i].id < 1) break;
		if (bpf_map_update_elem(filtersmap, &i, &cfg->filters[i], BPF_ANY) == -1) {
			perror("Error updating bpf map\n");
		}
	}
}

int update_config(struct f_config *cfg, char *cfgfile)
{
	if (open_config(cfgfile) != 0) {
		fprintf(stderr, "Error while opening filters config xdp.conf\n");
		return 1;
	}
	set_config_defaults(cfg);
	for (__u16 i = 0; i < MAX_FILTERS; i++) {
		cfg->filters[i] = (struct filter){0};
	}
	if (read_config(cfg) != 0) {
		fprintf(stderr, "Filters config invalid\n");
		return 1;
	}

	return 0;
}

int pinned_filters_upd(struct config *cfg)
{
	struct bpf_map_info info = {0};
	char pin_dir[PATH_MAX];
	int len;
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg->ifname);
	if (len < 0) {
		perror("Creating dir for pinning maps\n");
		return 1;
	}
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg->ifname);
	if (len < 0) {
		perror("Map name creation error\n");
		return 1;
	}
	int filters_map_fd = open_bpf_map_file(pin_dir, "filters_map", &info);
	if (filters_map_fd < 0) {
		return 1;
	}

	struct f_config filters_cfg = {0};
	set_config_defaults(&filters_cfg);
	update_config(&filters_cfg, "xdp.conf");
	update_filters(&filters_cfg, filters_map_fd);

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;
	int err;
	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex = -1,
		.do_unload = false,
	};
	printf("Started ... \n");
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	if (parse_cmdline(argc, argv, &cfg) != 0) {
		perror("Arguments parsing error\n");
		printf("%s\n", usage_msg);
		return 1;
	}

	if (cfg.ifindex == -1) {
		perror("No valid device specified\n");
		printf("%s\n", usage_msg);
		return 1;
	}

	if (cfg.do_unload) {
		char pin_dir[PATH_MAX];
		int offload_ifindex = 0;
		snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
		if (cfg.xdp_flags & XDP_FLAGS_HW_MODE)
			offload_ifindex = cfg.ifindex;
		bpf_obj = load_bpf_object_file(cfg.filename,
									   offload_ifindex);
		bpf_object__unpin_maps(bpf_obj, pin_dir);
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	}

	if (cfg.do_filters_update) {
		if ( pinned_filters_upd(&cfg) == 0 ) {
			printf("Updated filters\n");
		}
		return 0;
	}

	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj) return 1;
	printf("Loaded BPF (%s))\n", cfg.filename);
	printf(" == XDP attached on interface: %s (ifindex:%d)\n", cfg.ifname, cfg.ifindex);

	err = pin_maps_in_bpf_object(bpf_obj, cfg.ifname);
	if (err) {
		fprintf(stderr, "ERR: pinning maps\n");
		return err;
	}
	pinned_filters_upd(&cfg);

	return 0;
}
