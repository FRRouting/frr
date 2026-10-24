// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Split Horizon Filter implementation
 * Copyright (c) 2026 VyOS Inc
 * Kyrylo Yatsenko
 */

#ifndef _ZEBRA_SPLIT_HORIZON_FILTER_BPF_H
#define _ZEBRA_SPLIT_HORIZON_FILTER_BPF_H

/* When changing MAX_VTEP_CNT pay attention to FXMARK_DEFAULT_VTEP_ID_MASK_SHIFTED width */
#define MAX_UPLINK_CNT 32
#define MAX_VTEP_CNT 127
#define MAX_ES_CNT 32
#define FWMARK_DEFAULT_UPLINK_BIT_MASK 0x80000000
#define FWMARK_DEFAULT_VTEP_ID_SHIFT 24
#define FWMARK_DEFAULT_VTEP_ID_MASK_SHIFTED (0x7f << FWMARK_DEFAULT_VTEP_ID_SHIFT)

/* For each ES we need to remember each peer VTEP in this ES */
#define MAX_VTEP_BOND_CONNECTIONS_CNT 4096

/**
 * Struct for key in `vtep_bond_set`
 */
struct vtep_ifindex_pair {
	__u32 vtep_id;
	__s32 ifindex;
};

#endif /* _ZEBRA_SPLIT_HORIZON_FILTER_BPF_H */
