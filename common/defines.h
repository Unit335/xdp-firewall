#ifndef __DEFINES_H
#define __DEFINES_H

#include <net/if.h>
#include <linux/types.h>
#include <stdbool.h>

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool do_filters_update;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	__u16 xsk_bind_flags;
};

#endif /* __DEFINES_H */
