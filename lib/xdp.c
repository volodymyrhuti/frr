/* SPDX-License-Identifier: GPL-2.0 */
#include <zebra.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>

#include "xdp.h"
#include "log.h"
#include "prefix.h"
#include "privs.h"

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
#define XDP_QPPB_DSCP_MAP "dscp_map"

static const char *global_pins =  "/sys/fs/bpf/tc/globals";
static int dscp_map_fd;

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

void xdp_init()
{
	dscp_map_fd = open_bpf_map_file(global_pins, XDP_QPPB_DSCP_MAP);
	zlog_debug("Zebra XDP library initialization - %s",
	           dscp_map_fd < 0 ? "failed" : "successful");
}


void xdp_qppb_prefix_mark(const struct prefix *p, uint8_t dscp, bool add)
{
	struct bpf_lpm_trie_key *key_ipv4 = alloca(XDP_LPM_KEY_SIZE);
	int err;

	key_ipv4->prefixlen = p->prefixlen;
	*key_ipv4->data = p->u.prefix4.s_addr;
	err = add ? bpf_map_update_elem(dscp_map_fd, key_ipv4, &dscp, 0) :
		    bpf_map_delete_elem(dscp_map_fd, key_ipv4);
	zlog_debug("XDP %smark prefix [%pFX, dscp %d, err %d]",
		   add ? "":"un", p, dscp, err);
}

void _debug() {};
void test_lpm_map(void)
{
	struct bpf_lpm_trie_key *key_ipv4 = alloca(XDP_LPM_KEY_SIZE);
	size_t dscp;

	_debug();
	dscp = 0x10;
	key_ipv4->prefixlen = 16;
	inet_pton(AF_INET, "192.168.0.0", key_ipv4->data);
	assert(bpf_map_update_elem(dscp_map_fd, key_ipv4, &dscp, 0) == 0);
	
	dscp = 0x11;
	key_ipv4->prefixlen = 17;
	inet_pton(AF_INET, "192.169.0.0", key_ipv4->data);
	assert(bpf_map_update_elem(dscp_map_fd, key_ipv4, &dscp, 0) == 0);

	dscp = 0x12;
	key_ipv4->prefixlen = 18;
	inet_pton(AF_INET, "192.170.0.0", key_ipv4->data);
	assert(bpf_map_update_elem(dscp_map_fd, key_ipv4, &dscp, 0) == 0);
}

