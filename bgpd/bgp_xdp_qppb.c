// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * xdp_qppb.c
 * XDP handlers to mark/classify traffic by QPPB plugin
 *
 * Copyright (C) 2023 VyOS Inc.
 * Volodymyr Huti
 */

#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>

/* REFERENCES:
 * linux/samples/bpf/xdp_fwd_kernel.c
 * linux/samples/bpf/xdp_router_ipv4.bpf.c
 * linux/samples/bpf/xdp2skb_meta_kern.c
 * xdp-tutorial/packet-solutions/xdp_prog_kern_03.c
 * bcc/examples/networking/xdp_drop_count.py
 * bcc/examples/networking/tc_perf_event.py
 * xdp-cpumap-tc/src/tc_classify_kern.c
 */

#if (!defined(MARK_SKB) && !defined(MARK_META))
#error Specify marking mode to be used
#elif (defined(MARK_SKB) && defined(MARK_META))
#error Specify single mode only
#elif (!defined(MODE_STR))
#warn XXX : Poor config
#endif

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct lpm_key4 {
	__u32 prefixlen;
	__u32 src;
};

union lpm_key4_u {
	__u32 b32[2];
	__u8 b8[8];
};

#if !defined(XDP_ACTION_MAX)
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif
#if !defined(BPF_PIN_DIR)
#define BPF_PIN_DIR "/sys/fs/bpf"
#endif

#define DSCP_PIN BPF_PIN_DIR "/dscp_map"
#define QPPB_PIN BPF_PIN_DIR "/qppb_mode_map"
#if !defined(IFACE)
#define STAT_PIN BPF_PIN_DIR "/xdp_stats_map"
#else
#define STAT_PIN BPF_PIN_DIR "/" IFACE "/xdp_stats_map"
#endif
//               type : key :  leaf : name : size : pin_dir : flags
BPF_TABLE_PINNED("percpu_array", u32, struct datarec, xdp_stats_map,
		 XDP_ACTION_MAX, STAT_PIN);
BPF_TABLE_PINNED("lpm_trie", struct lpm_key4, u8, dscp_map, 10240, DSCP_PIN,
		 BPF_F_NO_PREALLOC);
BPF_TABLE_PINNED("array", u32 /*iface_id*/, u32 /*qppb_bgp_policy*/,
		 qppb_mode_map, 64, QPPB_PIN);
//               XXX: choose table size limits (read them from sysctl?)

enum qppb_bgp_policy {
	BGP_POLICY_NONE = 0,
	BGP_POLICY_DST = 1,
	BGP_POLICY_SRC = 2,
	BGP_POLICY_MAX
};

static __always_inline __u32 xdp_stats_record_action(struct xdp_md *ctx,
						     u32 action)
{
	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	struct datarec *rec = xdp_stats_map.lookup(&action);

	if (!rec)
		return XDP_ABORTED;
	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);
	return action;
}

/* Taken from include/net/dsfield.h */
static __always_inline void ipv4_change_dsfield(struct iphdr *iph, __u8 mask,
						__u8 value)
{
	__u32 check = bpf_ntohs((__be16)iph->check);
	__u8 dsfield;

	dsfield = (iph->tos & mask) | value;
	check += iph->tos;
	if ((check + 1) >> 16)
		check = (check + 1) & 0xffff;
	check -= dsfield;
	check += check >> 16; /* adjust carry */
	iph->check = (__sum16)bpf_htons(check);
	iph->tos = dsfield;
}

struct meta_info {
	__u8 mark;
} __attribute__((aligned(4)));

int xdp_qppb(struct xdp_md *ctx)
{
	int rc, action = XDP_PASS;
#if defined(MARK_META)
	struct meta_info *meta;

	rc = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (rc < 0)
		goto aborted;
#endif

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *iph = data + sizeof(struct ethhdr);
	__u64 nh_off = sizeof(struct ethhdr);
	__u32 ifindex = ctx->ingress_ifindex;
	union lpm_key4_u key4;
	__u8 *mark, qppb_mode;
	__u32 *qppb_mkey;
	__be16 h_proto;

	if (data + nh_off > data_end)
		goto drop;
	if ((void *)(iph + 1) > data_end)
		goto drop;
#if defined(MARK_META)
	meta = (void *)(long)ctx->data_meta;
	if ((void *)(meta + 1) > data)
		goto aborted;
#endif
	qppb_mkey = qppb_mode_map.lookup(&ifindex);
	qppb_mode = qppb_mkey ? *qppb_mkey : BGP_POLICY_NONE;
	// skip if bgp mode was not configured
	if (qppb_mode == BGP_POLICY_NONE)
		goto skip;

	h_proto = ((struct ethhdr *)data)->h_proto;
	if (h_proto != bpf_htons(ETH_P_IP) || iph->ttl <= 1)
		goto skip;
#if defined(RESPECT_TOS)
	if (iph->tos) {
#if defined(MARK_META)
		meta->mark = iph->tos;
#if defined(LOG_QPPB)
		bpf_trace_printk("XDP ignore marked packet [%d|%d]", iph->tos,
				 meta->mark);
#endif
#endif
		goto skip;
	}
#endif
	key4.b32[0] = 32;
	switch (qppb_mode) {
	case BGP_POLICY_DST:
		key4.b8[4] = iph->daddr & 0xff;
		key4.b8[5] = (iph->daddr >> 8) & 0xff;
		key4.b8[6] = (iph->daddr >> 16) & 0xff;
		key4.b8[7] = (iph->daddr >> 24) & 0xff;
		break;
	case BGP_POLICY_SRC:
		key4.b8[4] = iph->saddr & 0xff;
		key4.b8[5] = (iph->saddr >> 8) & 0xff;
		key4.b8[6] = (iph->saddr >> 16) & 0xff;
		key4.b8[7] = (iph->saddr >> 24) & 0xff;
		break;
	default:
		goto out;
	}

	mark = dscp_map.lookup((struct lpm_key4 *)&key4);
	if (!mark)
		goto out;
#if defined(MARK_SKB)
	ipv4_change_dsfield(iph, 0, *mark);
#elif defined(MARK_META)
	meta->mark = *mark;
#endif
#if defined(LOG_QPPB)
	bpf_trace_printk("XDP Mark detected [%d]\n", *mark);
#endif
out:
	return xdp_stats_record_action(ctx, action);
drop:
	return xdp_stats_record_action(ctx, XDP_DROP);
aborted:
	return xdp_stats_record_action(ctx, XDP_ABORTED); // packet is dropped
skip:
	return action;
}

int xdp_tc_mark(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_meta = (void *)(long)skb->data_meta;
	struct meta_info *meta = data_meta;

	// Default priority
	skb->tc_classid = 0x50;
	// Check XDP gave us some data_meta
	if ((void *)(meta + 1) > data)
		return TC_ACT_OK;
	if (!meta->mark)
		return TC_ACT_OK;

	/* skb->mark = meta->mark;  // Firewall fw mark */
	/* skb->priority = meta->mark; */
	switch (meta->mark >> 2) {
	case 10:
		skb->tc_classid = 0x10;
		break;
	case 20:
		skb->tc_classid = 0x20;
		break;
	case 30:
		skb->tc_classid = 0x30;
		break;
	case 40:
		skb->tc_classid = 0x40;
		break;
defaut:
		break;
	}

#if defined(LOG_TC)
	bpf_trace_printk("TC Mark detected [%d|%d|%d]", meta->mark,
			 meta->mark >> 2, skb->tc_classid);
#endif
	return TC_ACT_OK;
}
