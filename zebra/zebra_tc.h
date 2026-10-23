// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Traffic Control (TC) Data structures and definitions
 * These are public definitions referenced by multiple files.
 *
 * Copyright (C) 2022 Shichu Yang
 */

#ifndef _ZEBRA_TC_H
#define _ZEBRA_TC_H

#include <zebra.h>
#include "rt.h"
#include "tc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Major handle value zebra uses for TC qdiscs that it owns. Used both
 * when programming new qdiscs and when deciding whether a qdisc seen
 * via the kernel notification path was previously installed by zebra
 * (so that it can be cleaned up at startup).
 */
#define TC_QDISC_MAJOR_ZEBRA (0xbeef0000u)

/*
 * Filters that zebra derives on its own (as opposed to filters a ZAPI
 * client such as sharpd asks for by handle) set this bit in their
 * handle and carry ZEBRA_TC_ACT_COOKIE on their action.  Both are
 * checked before a filter found in the kernel at startup is treated as
 * a leftover of a previous zebra instance and removed.
 */
#define TC_FILTER_HANDLE_ZEBRA	(0x80000000u)
#define ZEBRA_TC_ACT_COOKIE	"FRRzebra"
#define ZEBRA_TC_ACT_COOKIE_LEN 8

/* Who asked for a filter */
enum zebra_tc_owner {
	ZEBRA_TC_OWNER_ZAPI = 0, /* ZEBRA_TC_FILTER_ADD from a client */
	ZEBRA_TC_OWNER_PBR,	 /* derived from a PBR rule */
};

/* Last known dataplane state of a filter */
enum zebra_tc_status {
	ZEBRA_TC_STATUS_QUEUED = 0,
	ZEBRA_TC_STATUS_INSTALLED,
	ZEBRA_TC_STATUS_FAILED,
};

struct zebra_tc_qdisc {
	int sock;

	struct tc_qdisc qdisc;
};

struct zebra_tc_class {
	int sock;

	struct tc_class class;
};

struct zebra_tc_filter {
	int sock;

	struct tc_filter filter;

	enum zebra_tc_owner owner;
	enum zebra_tc_status status;
};

const char *tc_qdisc_kind2str(uint32_t type);
enum tc_qdisc_kind tc_qdisc_str2kind(const char *type);

uint32_t zebra_tc_qdisc_hash_key(const void *arg);
bool zebra_tc_qdisc_hash_equal(const void *arg1, const void *arg2);
void zebra_tc_qdisc_install(struct zebra_tc_qdisc *qdisc);
void zebra_tc_qdisc_uninstall(struct zebra_tc_qdisc *qdisc);
void zebra_tc_qdisc_free(struct zebra_tc_qdisc *qdisc);

uint32_t zebra_tc_class_hash_key(const void *arg);
bool zebra_tc_class_hash_equal(const void *arg1, const void *arg2);
void zebra_tc_class_add(struct zebra_tc_class *class);
void zebra_tc_class_delete(struct zebra_tc_class *class);
void zebra_tc_class_free(struct zebra_tc_class *class);

const char *tc_filter_kind2str(uint32_t type);
enum tc_qdisc_kind tc_filter_str2kind(const char *type);
void zebra_tc_filter_add(struct zebra_tc_filter *filter);
void zebra_tc_filter_delete(struct zebra_tc_filter *filter);
void zebra_tc_filter_free(struct zebra_tc_filter *filter);

void zebra_tc_filters_free(void *arg);
struct zebra_tc_filter *zebra_tc_filter_lookup(ifindex_t ifindex, uint32_t handle,
					       enum tc_filter_attach attach);
/* Forget a filter without touching the dataplane (its interface is gone) */
void zebra_tc_filter_forget(struct zebra_tc_filter *filter);

/*
 * clsact qdisc reference counting.  zebra installs a clsact qdisc on the
 * first ingress/egress filter it adds to an interface and removes it with
 * the last one, unless the qdisc was already there (operator-owned), in
 * which case it is used and never removed.
 */
void zebra_tc_clsact_init(void);
void zebra_tc_clsact_ref(ifindex_t ifindex);
void zebra_tc_clsact_unref(ifindex_t ifindex, bool ifp_gone);
void zebra_tc_clsact_terminate(void);

struct vty;
struct json_object;
void zebra_tc_show(struct vty *vty, ifindex_t ifindex, struct json_object *json);
const char *zebra_tc_status2str(enum zebra_tc_status status);
uint32_t zebra_tc_filter_hash_key(const void *arg);
bool zebra_tc_filter_hash_equal(const void *arg1, const void *arg2);

/*
 * Master-pthread handler for kernel-originated TC qdisc notifications
 * (DPLANE_OP_TC_QDISC_NOTIFY ctx).
 */
struct zebra_dplane_ctx;
void zebra_tc_qdisc_handle_notify(struct zebra_dplane_ctx *ctx);

/* Master-pthread handler for TC qdisc/class/filter op results */
void zebra_tc_dplane_result(struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_TC_H */
