#include <bpf/libbpf.h> /* bpf_get_link_xdp_id + bpf_set_link_xdp_id */
#include <string.h>     /* strerror */
#include <net/if.h>     /* IF_NAMESIZE */
#include <stdlib.h>     /* exit(3) */
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_link.h> /* Need XDP flags */
#include <linux/err.h>
#include "defines.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	int err;
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		__u32 old_flags = xdp_flags;
		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}
	if (err < 0) {
		perror("link set xdp error\n");
		return 1;
	}
	return 0;
}

int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;
	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err) {
		perror("link get xdp error\n");
		return 1;
	}
	if (!curr_prog_id) {
		perror("No XDP program on this index\n");
		return 1;
	}
	if (expected_prog_id && curr_prog_id != expected_prog_id) {
		perror("prog id mismatch\n");
		return 1;
	}
	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		perror("link set xdp error\n");
		return 1;
	}

	printf("INFO: %s() removed XDP prog ID:%d on ifindex:%d\n",
		       __func__, curr_prog_id, ifindex);

	return 0;
}

struct bpf_object *load_bpf_object_file(const char *filename, int ifindex)
{
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.ifindex   = ifindex,
	};
	prog_load_attr.file = filename;
	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
	if (err) {
		perror("BPF-XDP object loading failed\n");
		return NULL;
	}
	return obj;
}


struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg)
{
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int offload_ifindex = 0;
	int prog_fd = -1;
	int err;
	if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
		offload_ifindex = cfg->ifindex;
	bpf_obj = load_bpf_object_file(cfg->filename, offload_ifindex);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
		exit(1);
	}
	if (cfg->progsec[0])
		bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
	else
		bpf_prog = bpf_program__next(NULL, bpf_obj);

	if (!bpf_prog) {
		perror("Program not found\n");
		exit(1);
	}

	strncpy(cfg->progsec, bpf_program__title(bpf_prog, false), sizeof(cfg->progsec));

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		perror("Program fd detection error\n");
		exit(1);
	}
	err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
	if (err)
		exit(err);

	return bpf_obj;
}

#define XDP_UNKNOWN	XDP_REDIRECT + 1
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)
#endif

int open_bpf_map_file(const char *pin_dir,
		      const char *mapname,
		      struct bpf_map_info *info)
{
	char filename[PATH_MAX];
	int err, len, fd;
	__u32 info_len = sizeof(*info);
	len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
	if (len < 0) {
		perror("Error while constructing full map path\n");
		return -1;
	}
	fd = bpf_obj_get(filename);
	if (fd < 0) {
		perror("Errow while opening BPF file\n");
		return fd;
	}
	if (info) {
		err = bpf_obj_get_info_by_fd(fd, info, &info_len);
		if (err) {
			perror("Error: can`t get info by bpf fd\n");
			return 1;
		}
	}

	return fd;
}
