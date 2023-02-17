// SPDX-License-Identifier: GPL-2.0-or-later
/* OSPF VTY interface.
 * Copyright (C) 2000 Toshiaki Takada
 */

#ifndef _QUAGGA_OSPF_VTY_H
#define _QUAGGA_OSPF_VTY_H

/* Macros. */
#define VTY_GET_OSPF_AREA_ID(V, F, STR)                                        \
	{                                                                      \
		int retv;                                                      \
		retv = str2area_id((STR), &(V), &(F));                         \
		if (retv < 0) {                                                \
			vty_out(vty, "%% Invalid OSPF area ID\n");             \
			return CMD_WARNING;                                    \
		}                                                              \
	}

#define VTY_GET_OSPF_AREA_ID_NO_BB(NAME, V, F, STR)                            \
	{                                                                      \
		int retv;                                                      \
		retv = str2area_id((STR), &(V), &(F));                         \
		if (retv < 0) {                                                \
			vty_out(vty, "%% Invalid OSPF area ID\n");             \
			return CMD_WARNING;                                    \
		}                                                              \
		if (OSPF_IS_AREA_ID_BACKBONE((V))) {                           \
			vty_out(vty,                                           \
				"%% You can't configure %s to backbone\n",     \
				NAME);                                         \
			return CMD_WARNING;                                    \
		}                                                              \
	}

/* Prototypes. */
extern void ospf_vty_init(void);
extern void ospf_vty_show_init(void);
extern void ospf_vty_clear_init(void);
extern int str2area_id(const char *, struct in_addr *, int *);

/* unit tests */
void show_ip_ospf_database_summary(struct vty *vty, struct ospf *ospf, int self,
				   json_object *json);

#endif /* _QUAGGA_OSPF_VTY_H */
