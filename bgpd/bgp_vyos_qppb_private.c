#include <zebra.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bgpd/bgpd.h"
#include "log.h"
#include "prefix.h"
#include "privs.h"

#define BPF_DSCP_MAP "dscp_map"
#define BPF_PIN_DIR "/sys/fs/bpf/"
#define TC_PIN_DIR BPF_PIN_DIR "tc/globals"

/* data[0] - a stretchy buf, sizeof() doesn`t count for it 
 * struct bpf_lpm_trie_key {
 *      __u32 prefixlen;
 *      __u8 data[0];
 * }; */
#define BPF_LPM_KEY_SIZE (sizeof(struct bpf_lpm_trie_key) + sizeof(__u32))

static int open_bpf_map_file(const char *pin_dir, const char *mapname)
{
	char filename[PATH_MAX];
	int len, fd;

	len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
	if (len < 0) {
		zlog_err("Failed constructing BPF map path");
		return -1;
	}

	fd = bpf_obj_get(filename);
	if (fd < 0)
		zlog_err("Failed to open bpf map file [%s - err(%d):%s]",
			 filename, errno, strerror(errno));
	return fd;
}

static int dscp_map_fd;
static void bgp_qppb_init(void)
{
	const char *pin_dir = THIS_MODULE->load_args ? : BPF_PIN_DIR;

	dscp_map_fd = open_bpf_map_file(pin_dir, BPF_DSCP_MAP);
	if (dscp_map_fd < 0)
		zlog_err("DSCP map open failed, path: %s/%s",
			 pin_dir, BPF_DSCP_MAP);
}

extern struct zebra_privs_t bgpd_privs;
static int bgp_qppb_mark_prefix(const struct prefix *p, uint8_t dscp, bool add)
{
	struct bpf_lpm_trie_key *key_ipv4;
	int err = 0;

	if (!dscp) {
		zlog_debug("QPPB unmarked route update [%pFX]", p);
		return err;
        }

	key_ipv4 = alloca(BPF_LPM_KEY_SIZE);
	key_ipv4->prefixlen = p->prefixlen;
	memcpy(key_ipv4->data, &p->u.prefix4, sizeof(struct in_addr));

	frr_with_privs(&bgpd_privs) {
		err = add ? bpf_map_update_elem(dscp_map_fd, key_ipv4, &dscp, 0) :
			    bpf_map_delete_elem(dscp_map_fd, key_ipv4);
	}

	zlog_info("QPPB %s prefix [%pFX| dscp %d, err %d]",
		  add ? "mark":"unmark", p, dscp, err);
	return err;
}

static int bgp_qppb_module_init(void) {
	bgp_qppb_init();
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
