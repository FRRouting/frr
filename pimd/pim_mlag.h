/*
 * This is an implementation of PIM MLAG Functionality
 *
 * Module name: PIM MLAG
 *
 * Author: sathesh Kumar karra <sathk@cumulusnetworks.com>
 *
 * Copyright (C) 2019 Cumulus Networks http://www.cumulusnetworks.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __PIM_MLAG_H__
#define __PIM_MLAG_H__

#include "zclient.h"
#include "mlag.h"
#include "pim_iface.h"

#if PIM_IPV == 4
extern void pim_mlag_init(void);
extern void pim_mlag_terminate(void);
extern void pim_instance_mlag_init(struct pim_instance *pim);
extern void pim_instance_mlag_terminate(struct pim_instance *pim);
extern void pim_if_configure_mlag_dualactive(struct pim_interface *pim_ifp);
extern void pim_if_unconfigure_mlag_dualactive(struct pim_interface *pim_ifp);
extern int pim_zebra_mlag_process_up(ZAPI_CALLBACK_ARGS);
extern int pim_zebra_mlag_process_down(ZAPI_CALLBACK_ARGS);
extern int pim_zebra_mlag_handle_msg(ZAPI_CALLBACK_ARGS);

/* pm_zpthread.c */
extern int pim_mlag_signal_zpthread(void);
extern void pim_zpthread_init(void);
extern void pim_zpthread_terminate(void);

extern void pim_mlag_register(void);
extern void pim_mlag_deregister(void);
extern void pim_mlag_up_local_add(struct pim_instance *pim,
				  struct pim_upstream *upstream);
extern void pim_mlag_up_local_del(struct pim_instance *pim,
				  struct pim_upstream *upstream);
extern bool pim_mlag_up_df_role_update(struct pim_instance *pim,
				       struct pim_upstream *up, bool is_df,
				       const char *reason);
#else /* PIM_IPV == 4 */
static inline void pim_mlag_terminate(void)
{
}

static inline void pim_instance_mlag_init(struct pim_instance *pim)
{
}

static inline void pim_instance_mlag_terminate(struct pim_instance *pim)
{
}

static inline void pim_if_configure_mlag_dualactive(
						struct pim_interface *pim_ifp)
{
}

static inline void pim_if_unconfigure_mlag_dualactive(
						struct pim_interface *pim_ifp)
{
}

static inline void pim_mlag_register(void)
{
}

static inline void pim_mlag_up_local_add(struct pim_instance *pim,
					 struct pim_upstream *upstream)
{
}

static inline void pim_mlag_up_local_del(struct pim_instance *pim,
					 struct pim_upstream *upstream)
{
}

static inline bool pim_mlag_up_df_role_update(struct pim_instance *pim,
					      struct pim_upstream *up,
					      bool is_df, const char *reason)
{
	return false;
}
#endif

#endif
