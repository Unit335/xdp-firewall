#ifndef __BPPXDP_H
#define __BPPXDP_H
#include <net/if.h>
#include <linux/types.h>
#include <stdbool.h>
#include "defines.h"

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd);
int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id);

struct bpf_object *load_bpf_object_file(const char *filename, int ifindex);
struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg);

const char *action2str(__u32 action);

int open_bpf_map_file(const char *pin_dir,
		      const char *mapname,
		      struct bpf_map_info *info);

#endif /* __BPPXDP_H */
