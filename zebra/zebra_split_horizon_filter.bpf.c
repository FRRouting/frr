// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Split Horizon Filter implementation
 * Copyright (c) 2026 VyOS Inc
 * Kyrylo Yatsenko
 */

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

#ifndef TCX_PASS
#define TCX_PASS 0
#endif

#ifndef TCX_DROP
#define TCX_DROP 2
#endif

#define MAX_VTEP_CNT 128
#define MAX_ES_CNT 32
/* For each ES we need to remember each peer VTEP in this ES */
#define MAX_VTEP_BOND_CONNECTIONS_CNT 1024

/* 127.0.0.1 won't be used by remote VTEPs */
#define LOCAL_MARK 0x0100007f

/* #define DEBUG */

char LICENSE[] SEC("license") = "GPL";

/**
 * Maps VTEP IPv4 addresses to VTEP ids
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __u32);
    __uint(max_entries, MAX_VTEP_CNT);
} ip_to_vtep_id SEC(".maps");

/**
 * Map (VTEP id, ifindex) -> u8
 * We need set here, but it is not supported by BPF, so waste a bype per entry.
 * If (VTEP, ifindex) pair is in this set, the VTEP is peer in ES of bond with ifindex
 */
struct vtep_ifindex_pair  {
    __u32 vtep_id;
    __s32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vtep_ifindex_pair);
    __type(value, __u8);
    __uint(max_entries, MAX_VTEP_BOND_CONNECTIONS_CNT);
} vtep_bond_set SEC(".maps");

/**
 * Map ifindex -> u8
 * For each bond 1 if we are DF on it and 0 if not
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, MAX_ES_CNT);
} is_df_on_bond SEC(".maps");

/**
 * Split Horizon Filter, should be attached to each uplink interface
 *
 * 1. Check if it is IPv4/IPv6 (IPv6 TODO)
 * 2. If so, check that source IP is one of any ES neighbors
 * 3. If so, check that transport protocol is UDP with VXLAN data (TODO)
 * 4. Then set mark with VTEP id
 */
SEC("tcx/ingress")
int split_horizon_filter_uplink(struct __sk_buff *skb)
{
	__be32 ipv4_saddr;
	__u32 *pval;
	switch (skb->protocol) {
		case bpf_htons(ETH_P_IP):
			bpf_skb_load_bytes_relative(
				skb,
				offsetof(struct iphdr, saddr),
				&ipv4_saddr,
				sizeof(__be32),
				BPF_HDR_START_NET);
			skb->mark = ipv4_saddr;
			pval = bpf_map_lookup_elem(&ip_to_vtep_id, &ipv4_saddr);
			if (pval) {
				skb->mark = *pval;
			} else {
				skb->mark = 0;
			}
			break;
		/* TODO add IPv6 support */
	}
	return TCX_NEXT;
}

/**
 * Split Horizon Filter, should be attached to bond interface
 *
 * If we are non-DF: filter any BUM traffic except originated from hosts
 * If we are DF: filter any BUM traffic with mark equal to interface index
 */
SEC("tcx/egress")
int split_horizon_filter_bond(struct __sk_buff *skb)
{
	/* We are interested in BUM only */
	/* TODO Unknown Unicast case */
	if (skb->pkt_type != PACKET_BROADCAST && skb->pkt_type != PACKET_MULTICAST) {
#ifdef DEBUG
		bpf_printk("%s: ifindex: %u, not BUM, passing", __func__, skb->ifindex);
#endif
		return TCX_NEXT;
	}
	
	__u8 *pis_df;
	/* Somewhy fails if using skb->ifindex directly... */
	__u32 key_ifindex = skb->ifindex;
	pis_df = bpf_map_lookup_elem(&is_df_on_bond, &key_ifindex);
	if (!pis_df) {
#ifdef DEBUG
		bpf_printk("%s: WARNING Unknown DF!!! We shouldn't be here, ifindex: %u", __func__, skb->ifindex);
#endif
		return TCX_NEXT;
	}

	__u8 is_df = *pis_df;

	if (!is_df) {
#ifdef DEBUG
		bpf_printk("%s: !DF, drop: ifindex: %u, mark: 0x%x, pkt_type: %d, verdict: %s", __func__, skb->ifindex, skb->mark, skb->pkt_type, (skb->mark == LOCAL_MARK) ? "TCX_NEXT" : "TCX_DROP");
#endif
		return (skb->mark == LOCAL_MARK) ? TCX_NEXT : TCX_DROP;
	}
	struct vtep_ifindex_pair vip = {.ifindex = skb->ifindex, .vtep_id = skb->mark};
	__u8 *p = bpf_map_lookup_elem(&vtep_bond_set, &vip);

#ifdef DEBUG
	bpf_printk("%s: DF, ifindex: %u, mark: 0x%x, pkt_type: %d, verdict: %s\n", __func__, skb->ifindex, skb->mark, skb->pkt_type,
			p ? "TCX_DROP" : "TCX_NEXT");
#endif
	return p ? TCX_DROP : TCX_NEXT;
}

/**
 * Mark all packets that came from bonds with special mark
 */
SEC("tcx/ingress")
int split_horizon_filter_bond_ingress(struct __sk_buff *skb)
{
#ifdef DEBUG
	bpf_printk("%s: setting mark to LOCAL_MARK", __func__);
#endif
	skb->mark = LOCAL_MARK;
	return TCX_NEXT;
}
