/* PIM mlag header.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef __PIM_MLAG_H__
#define __PIM_MLAG_H__

#include "mlag.h"
#include "pim_iface.h"

extern void pim_mlag_init(void);

extern void pim_instance_mlag_init(struct pim_instance *pim);

extern void pim_instance_mlag_terminate(struct pim_instance *pim);

extern void pim_if_configure_mlag_dualactive(struct pim_interface *pim_ifp);

extern void pim_if_unconfigure_mlag_dualactive(struct pim_interface *pim_ifp);

extern void pim_mlag_register(void);

extern void pim_mlag_deregister(void);

extern int pim_zebra_mlag_process_up(void);

extern int pim_zebra_mlag_process_down(void);

extern int pim_zebra_mlag_handle_msg(struct stream *msg, int len);

#endif
