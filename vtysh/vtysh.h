/* Virtual terminal interface shell.
 * Copyright (C) 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef VTYSH_H
#define VTYSH_H

#include "memory.h"
DECLARE_MGROUP(MVTYSH);

struct thread_master;

extern struct thread_master *master;

#define VTYSH_ZEBRA     0x00001
#define VTYSH_RIPD      0x00002
#define VTYSH_RIPNGD    0x00004
#define VTYSH_OSPFD     0x00008
#define VTYSH_OSPF6D    0x00010
#define VTYSH_BGPD      0x00020
#define VTYSH_ISISD     0x00040
#define VTYSH_PIMD      0x00080
#define VTYSH_LDPD      0x00100
#define VTYSH_WATCHFRR  0x00200
#define VTYSH_NHRPD     0x00400
#define VTYSH_EIGRPD    0x00800
#define VTYSH_BABELD    0x01000
#define VTYSH_SHARPD    0x02000
#define VTYSH_PBRD      0x04000
#define VTYSH_STATICD   0x08000
#define VTYSH_BFDD      0x10000
#define VTYSH_FABRICD   0x20000
#define VTYSH_VRRPD     0x40000
#define VTYSH_PATHD     0x80000
#define VTYSH_PIM6D     0x100000

#define VTYSH_WAS_ACTIVE (-2)

/* commands in REALLYALL are crucial to correct vtysh operation */
#define VTYSH_REALLYALL	  ~0U
/* watchfrr is not in ALL since library CLI functions should not be
 * run on it (logging & co. should stay in a fixed/frozen config, and
 * things like prefix lists are not even initialised) */
#define VTYSH_ALL        VTYSH_ZEBRA|VTYSH_RIPD|VTYSH_RIPNGD|VTYSH_OSPFD|VTYSH_OSPF6D|VTYSH_LDPD|VTYSH_BGPD|VTYSH_ISISD|VTYSH_PIMD|VTYSH_PIM6D|VTYSH_NHRPD|VTYSH_EIGRPD|VTYSH_BABELD|VTYSH_SHARPD|VTYSH_PBRD|VTYSH_STATICD|VTYSH_BFDD|VTYSH_FABRICD|VTYSH_VRRPD|VTYSH_PATHD
#define VTYSH_ACL         VTYSH_BFDD|VTYSH_BABELD|VTYSH_BGPD|VTYSH_EIGRPD|VTYSH_ISISD|VTYSH_FABRICD|VTYSH_LDPD|VTYSH_NHRPD|VTYSH_OSPF6D|VTYSH_OSPFD|VTYSH_PBRD|VTYSH_PIMD|VTYSH_PIM6D|VTYSH_RIPD|VTYSH_RIPNGD|VTYSH_VRRPD|VTYSH_ZEBRA
#define VTYSH_RMAP       VTYSH_ZEBRA|VTYSH_RIPD|VTYSH_RIPNGD|VTYSH_OSPFD|VTYSH_OSPF6D|VTYSH_BGPD|VTYSH_ISISD|VTYSH_PIMD|VTYSH_EIGRPD|VTYSH_FABRICD
#define VTYSH_INTERFACE_SUBSET                                                 \
	VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_RIPNGD | VTYSH_OSPFD | VTYSH_OSPF6D | \
		VTYSH_ISISD | VTYSH_PIMD | VTYSH_PIM6D | VTYSH_NHRPD |         \
		VTYSH_EIGRPD | VTYSH_BABELD | VTYSH_PBRD | VTYSH_FABRICD |     \
		VTYSH_VRRPD
#define VTYSH_INTERFACE VTYSH_INTERFACE_SUBSET | VTYSH_BGPD
#define VTYSH_VRF VTYSH_INTERFACE_SUBSET | VTYSH_STATICD
#define VTYSH_KEYS VTYSH_RIPD | VTYSH_EIGRPD | VTYSH_OSPF6D
/* Daemons who can process nexthop-group configs */
#define VTYSH_NH_GROUP    VTYSH_PBRD|VTYSH_SHARPD
#define VTYSH_SR          VTYSH_ZEBRA|VTYSH_PATHD
#define VTYSH_DPDK VTYSH_ZEBRA

enum vtysh_write_integrated {
	WRITE_INTEGRATED_UNSPECIFIED,
	WRITE_INTEGRATED_NO,
	WRITE_INTEGRATED_YES
};

extern enum vtysh_write_integrated vtysh_write_integrated;

extern char frr_config[];
extern char vtydir[];
extern bool vtysh_loop_exited;

void vtysh_init_vty(void);
void vtysh_uninit(void);
void vtysh_init_cmd(void);
extern int vtysh_connect_all(const char *optional_daemon_name);
void vtysh_readline_init(void);
void vtysh_user_init(void);

int vtysh_execute(const char *);
int vtysh_execute_no_pager(const char *);
int vtysh_execute_command_questionmark(char *input);

char *vtysh_prompt(void);

void vtysh_config_write(void);

int vtysh_config_from_file(struct vty *, FILE *);

void config_add_line(struct list *, const char *);

int vtysh_mark_file(const char *filename);

int vtysh_read_config(const char *filename, bool dry_run);
int vtysh_write_config_integrated(void);

void vtysh_config_parse_line(void *, const char *);

void vtysh_config_dump(void);

void vtysh_config_init(void);

void suid_on(void);
void suid_off(void);

/* Child process execution flag. */
extern int execute_flag;

extern struct vty *vty;

extern int user_mode;

extern bool vtysh_add_timestamp;

#endif /* VTYSH_H */
