/*
 * generic CLI test helper functions
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _COMMON_CLI_H
#define _COMMON_CLI_H

#include "zebra.h"
#include "vty.h"
#include "command.h"

/* function to be implemented by test */
extern void test_init (void);

/* functions provided by common cli
 * (includes main())
 */
extern struct thread_master *master;

extern int dump_args(struct vty *vty, const char *descr,
              int argc, const char **argv);

#define DUMMY_HELPSTR \
       "00\n01\n02\n03\n04\n05\n06\n07\n08\n09\n" \
       "10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n" \
       "20\n21\n22\n23\n24\n25\n26\n27\n28\n29\n"
#define DUMMY_DEFUN(name, cmdstr) \
        DEFUN (name, name ## _cmd, cmdstr, DUMMY_HELPSTR) \
        { return dump_args(vty, #name, argc, argv); }

#endif /* _COMMON_CLI_H */
