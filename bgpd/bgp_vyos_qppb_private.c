#include <zebra.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bgpd/bgpd.h"
#include "log.h"
#include "prefix.h"
#include "privs.h"

#define XDP_QPPB_DSCP_MAP "dscp_map"
static const char *global_pins = "/sys/fs/bpf/"; // tc/globals
static int dscp_map_fd = -2;

static int open_bpf_map_file(const char *pin_dir, const char *mapname)
{
	char filename[PATH_MAX];
	int len, fd;

	len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
	if (len < 0) {
		zlog_err("Failed constructing xdp map path");
		return -1;
	}

	fd = bpf_obj_get(filename);
	if (fd < 0)
		zlog_err("Failed to open bpf map file :%s err(%d):%s",
			filename, errno, strerror(errno));

	return fd;
}

static void state_dump(void)
{
	zlog_debug("UID _ UID %d | EUID %d", getuid(), geteuid());
	zlog_debug("UID _ GID %d | EGID %d", getgid(), getegid());
	zlog_debug("Zebra XDP library initialization - %s (%d)",
		     dscp_map_fd < 0 ? "failed" : "successful", dscp_map_fd);
}

static void bgp_xdp_init(void)
{
        uid_t uid = getuid();
	if (setuid(0))
	    zlog_debug("Failed setuid err(%d):%s", errno, strerror(errno));

	dscp_map_fd = open_bpf_map_file(global_pins, XDP_QPPB_DSCP_MAP);
	if (dscp_map_fd < 0)
		zlog_debug("Failed to open dscp map %s(%d)",
			    strerror(errno), errno);
	else
		zlog_debug("XDP Init [%d]", dscp_map_fd);

	state_dump();
	if (setuid(uid))
	    zlog_debug("Failed unsetuid err(%d):%s", errno, strerror(errno));
}

/*
 * bpf_lpm_trie_key is a stretchy buf, meaning last member field is buf[0]
 * which is not counted by sizeof()
 * 	struct bpf_lpm_trie_key {
 * 		__u32 prefixlen;
 * 		__u8 data[0];
 * 	};
 * threfore, we need to include prefix size mannualy
 */
#define XDP_LPM_KEY_SIZE (sizeof(struct bpf_lpm_trie_key) + sizeof(__u32))

static int bgp_qppb_mark_prefix(const struct prefix *p, uint8_t dscp, bool add)
{
	struct bpf_lpm_trie_key *key_ipv4 = alloca(XDP_LPM_KEY_SIZE);
	int err;

	key_ipv4->prefixlen = p->prefixlen;
	memcpy(key_ipv4->data, &p->u.prefix4, sizeof(struct in_addr));
	err = add ? bpf_map_update_elem(dscp_map_fd, key_ipv4, &dscp, 0) :
		    bpf_map_delete_elem(dscp_map_fd, key_ipv4);
	zlog_debug("XDP %smark prefix [%pFX|%d| dscp %d, err %d]",
		   add ? "":"un", p, p->u.prefix4.s_addr, dscp, err);
	return err;
}

extern struct zebra_privs_t bgpd_privs;
static int bgp_qppb_module_init(void) {
	frr_with_privs (&bgpd_privs) {
		bgp_xdp_init();
	}
	hook_register(bgp_qppb_mark_prefix,
		      bgp_qppb_mark_prefix);
	return 0;
}

FRR_MODULE_SETUP(
	.name = "bgp_vyos_qppb",
	.version = "0.0.1",
	.description = "bgp QPPB implementation for VyOS",
	.init = bgp_qppb_module_init,
);
