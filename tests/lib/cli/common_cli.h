// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * generic CLI test helper functions
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
 */

#ifndef _COMMON_CLI_H
#define _COMMON_CLI_H

#include "zebra.h"
#include "vty.h"
#include "command.h"
#include "northbound.h"

extern const struct frr_yang_module_info *const *test_yang_modules;

/* function to be implemented by test */
extern void test_init(int argc, char **argv);

/* functions provided by common cli
 * (includes main())
 */
extern struct event_loop *master;

extern int test_log_prio;

extern int dump_args(struct vty *vty, const char *descr, int argc,
		     struct cmd_token *argv[]);

#define DUMMY_HELPSTR                                                          \
	"00\n01\n02\n03\n04\n05\n06\n07\n08\n09\n"                             \
	"10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n"                             \
	"20\n21\n22\n23\n24\n25\n26\n27\n28\n29\n"
#define DUMMY_DEFUN(name, cmdstr)                                              \
	DEFUN(name, name##_cmd, cmdstr, DUMMY_HELPSTR)                         \
	{                                                                      \
		return dump_args(vty, #name, argc, argv);                      \
	}

#endif /* _COMMON_CLI_H */
