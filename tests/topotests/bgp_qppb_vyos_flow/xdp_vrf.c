// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * XDP handler from mark/classifing traffic
 * Copyright (C) 2023 VyOS Inc.
 * Volodymyr Huti
 */

#include <bcc/proto.h>

int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}

#if !defined(BPF_PIN_DIR)
#define BPF_PIN_DIR "/sys/fs/bpf"
#endif

#define VRF_PIN  BPF_PIN_DIR "/vrf_map"
//               type : key :  leaf : name : size : pin_dir : flags
BPF_TABLE_PINNED("array", u32 /*dscp*/, u32 /*vrf*/, dscp_iface_map, 100, VRF_PIN);
int xdp_vrf(struct __sk_buff *skb)
{
	u8 *cursor = 0;
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	u32 tos, eif, *eifp, rc;

	tos = ip->tos;
	bpf_trace_printk("-- XDP [%d] --", tos);
	eifp = dscp_iface_map.lookup(&tos);
	if (!eifp)
		goto out;

	eif = *eifp;
	if (eif <= 0 || eif >= 100)
		// XXX: validate that ifid exists
		goto out;

	rc = bpf_redirect(eif, 0);
	bpf_trace_printk("[eif=%d|act=%d] Redir", eif, rc);
out:    return 1;
}

