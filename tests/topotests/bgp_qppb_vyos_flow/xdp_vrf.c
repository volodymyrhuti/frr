// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * XDP handler from mark/classifing traffic
 * Copyright (C) 2023 VyOS Inc.
 * Volodymyr Huti
 */

#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>

int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}

#if !defined(BPF_PIN_DIR)
#define BPF_PIN_DIR "/sys/fs/bpf"
#endif

#define VRF_PIN  BPF_PIN_DIR "/vrf_map"
//               type : key :  leaf : name : size : pin_dir : flags
BPF_TABLE_PINNED("array", u32 /*dscp*/, u32 /*vrf*/, dscp_iface_map, 100, VRF_PIN);

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

int xdp_vrf(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int action = XDP_PASS;
	u32 tos, eif, *eifp;
	struct iphdr *iph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	if (h_proto != bpf_htons(ETH_P_IP)){
		/* bpf_trace_printk("Proto [%d == %d]", */
		/* 		 h_proto, bpf_htons(ETH_P_IP)); */
		goto out;
	}

	iph = data + nh_off;
	if (iph + 1 > data_end) {
		action = XDP_DROP;
		goto out;
	}
	if (iph->ttl <= 1)
		goto out;

	tos = iph->tos;
	eifp = dscp_iface_map.lookup(&tos);
	if (!eifp)
		goto out;
	eif = *eifp;
	bpf_trace_printk("-- XDP lookup [%d|%d] --", tos, eif);
	if (eif <= 0 || eif >= 100)
		// XXX: validate that ifid exists
		goto out;

	bpf_trace_printk("Fib Lookup");
	struct bpf_fib_lookup fib_params = {};
	int lookup = BPF_FIB_LOOKUP_OUTPUT | BPF_FIB_LOOKUP_DIRECT;
	/* __builtin_memset(&fib_params, 0, sizeof(fib_params)); */
	fib_params.ifindex	= eif;
	fib_params.family	= AF_INET;
	fib_params.tos		= iph->tos;
	fib_params.ipv4_src	= iph->saddr;
	fib_params.ipv4_dst	= iph->daddr;
	fib_params.l4_protocol	= iph->protocol;
	fib_params.tot_len	= bpf_ntohs(iph->tot_len);

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), lookup);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		bpf_trace_printk("DROP");
		action = XDP_DROP;
		// fallthrough
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		bpf_trace_printk("NOTFW %d", rc);
		/* PASS */
		goto out;
	}

	ip_decrease_ttl(iph);
	memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
	memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
	action = bpf_redirect(eif, 0);
	bpf_trace_printk("[tos=%d|act=%d] Redir", tos, action);
	bpf_trace_printk("[iif=%d|fif=%d]", ctx->ingress_ifindex, fib_params.ifindex);

out:    return action;
}
// BPF_TABLE_PINNED("array", u32 /*dscp*/, u32 /*vrf*/, port_map, 100, PORT_PIN);
/* BPF_DEVMAP(port_map, 50); */
// XXX: lookup method is not available for the pinned handle (???)
/* BPF_TABLE_PINNED("devmap", u32 /1* - *1/, u32 /1* - *1/, port_map, 50, PORT_PIN); */
/* #define PORT_PIN  BPF_PIN_DIR "/port_map" */
