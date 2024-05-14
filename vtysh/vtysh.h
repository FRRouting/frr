// SPDX-License-Identifier: GPL-2.0-or-later
/* Virtual terminal interface shell.
 * Copyright (C) 2000 Kunihiro Ishiguro
 */

#ifndef VTYSH_H
#define VTYSH_H

#include "memory.h"
DECLARE_MGROUP(MVTYSH);

struct event_loop;

extern struct event_loop *master;

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
#define VTYSH_MGMTD 0x200000

#define VTYSH_WAS_ACTIVE (-2)

/* commands in REALLYALL are crucial to correct vtysh operation */
#define VTYSH_REALLYALL	  ~0U
/* watchfrr is not in ALL since library CLI functions should not be
 * run on it (logging & co. should stay in a fixed/frozen config, and
 * things like prefix lists are not even initialised) */
#define VTYSH_ALL                                                              \
	VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_RIPNGD | VTYSH_OSPFD | VTYSH_OSPF6D | \
		VTYSH_LDPD | VTYSH_BGPD | VTYSH_ISISD | VTYSH_PIMD |           \
		VTYSH_PIM6D | VTYSH_NHRPD | VTYSH_EIGRPD | VTYSH_BABELD |      \
		VTYSH_SHARPD | VTYSH_PBRD | VTYSH_STATICD | VTYSH_BFDD |       \
		VTYSH_FABRICD | VTYSH_VRRPD | VTYSH_PATHD | VTYSH_MGMTD
#define VTYSH_ACL_CONFIG                                                       \
	VTYSH_BFDD | VTYSH_BABELD | VTYSH_BGPD | VTYSH_EIGRPD | VTYSH_ISISD |  \
		VTYSH_FABRICD | VTYSH_LDPD | VTYSH_NHRPD | VTYSH_OSPF6D |      \
		VTYSH_OSPFD | VTYSH_PBRD | VTYSH_PIMD | VTYSH_PIM6D |          \
		VTYSH_VRRPD | VTYSH_MGMTD
#define VTYSH_ACL_SHOW                                                         \
	VTYSH_BFDD | VTYSH_BABELD | VTYSH_BGPD | VTYSH_EIGRPD | VTYSH_ISISD |  \
		VTYSH_FABRICD | VTYSH_LDPD | VTYSH_NHRPD | VTYSH_OSPF6D |      \
		VTYSH_OSPFD | VTYSH_PBRD | VTYSH_PIMD | VTYSH_PIM6D |          \
		VTYSH_RIPD | VTYSH_RIPNGD | VTYSH_VRRPD | VTYSH_ZEBRA

#define VTYSH_AFFMAP VTYSH_ISISD | VTYSH_MGMTD
#define VTYSH_RMAP_CONFIG                                                      \
	VTYSH_OSPFD | VTYSH_OSPF6D | VTYSH_BGPD | VTYSH_ISISD |  \
		VTYSH_PIMD | VTYSH_EIGRPD | VTYSH_FABRICD | VTYSH_MGMTD
#define VTYSH_RMAP_SHOW                                                        \
	VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_RIPNGD | VTYSH_OSPFD | VTYSH_OSPF6D | \
		VTYSH_BGPD | VTYSH_ISISD | VTYSH_PIMD | VTYSH_EIGRPD |         \
		VTYSH_FABRICD
#define VTYSH_ACCESS_LIST_SHOW                                                 \
	VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_RIPNGD | VTYSH_OSPFD | VTYSH_OSPF6D | \
		VTYSH_BGPD | VTYSH_ISISD | VTYSH_PIMD | VTYSH_EIGRPD |         \
		VTYSH_FABRICD
#define VTYSH_PREFIX_LIST_SHOW                                                 \
	VTYSH_ZEBRA | VTYSH_RIPD | VTYSH_RIPNGD | VTYSH_OSPFD | VTYSH_OSPF6D | \
		VTYSH_BGPD | VTYSH_ISISD | VTYSH_PIMD | VTYSH_EIGRPD |         \
		VTYSH_FABRICD
#define VTYSH_INTERFACE_SUBSET                                                 \
	VTYSH_OSPFD | VTYSH_OSPF6D | \
		VTYSH_ISISD | VTYSH_PIMD | VTYSH_PIM6D | VTYSH_NHRPD |         \
		VTYSH_EIGRPD | VTYSH_BABELD | VTYSH_PBRD | VTYSH_FABRICD |     \
		VTYSH_VRRPD | VTYSH_MGMTD
#define VTYSH_INTERFACE VTYSH_INTERFACE_SUBSET | VTYSH_BGPD
#define VTYSH_VRF	VTYSH_INTERFACE_SUBSET | VTYSH_BGPD
#define VTYSH_KEYS VTYSH_MGMTD | VTYSH_EIGRPD | VTYSH_OSPF6D | VTYSH_OSPFD
/* Daemons who can process nexthop-group configs */
#define VTYSH_NH_GROUP    VTYSH_PBRD|VTYSH_SHARPD
#define VTYSH_SR          VTYSH_ZEBRA|VTYSH_PATHD
#define VTYSH_DPDK VTYSH_ZEBRA
#define VTYSH_MGMT_BACKEND                                                     \
	VTYSH_RIPD | VTYSH_RIPNGD | VTYSH_STATICD | VTYSH_ZEBRA
#define VTYSH_MGMT_FRONTEND VTYSH_MGMTD

enum vtysh_write_integrated {
	WRITE_INTEGRATED_UNSPECIFIED,
	WRITE_INTEGRATED_NO,
	WRITE_INTEGRATED_YES
};

enum display_type {
	normal_display,
	summary_display,
	detail_display,
	sequential_display,
	longer_display,
	first_match_display
};

extern enum vtysh_write_integrated vtysh_write_integrated;
extern enum display_type display_type;

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

int vtysh_apply_config(const char *config_file_path, bool dry_run, bool fork);
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

struct vtysh_client {
	int fd;
	const char *name;
	int flag;
	char path[MAXPATHLEN];
	struct vtysh_client *next;

	struct event *log_reader;
	int log_fd;
	uint32_t lost_msgs;
};

extern struct vtysh_client vtysh_client[22];

#endif /* VTYSH_H */
