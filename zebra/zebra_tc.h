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
uint32_t zebra_tc_filter_hash_key(const void *arg);
bool zebra_tc_filter_hash_equal(const void *arg1, const void *arg2);

void kernel_read_tc_qdisc(struct zebra_ns *zns);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_TC_H */
