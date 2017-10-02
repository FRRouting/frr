/*
 * EIGRP Macros Definition.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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

#ifndef _ZEBRA_EIGRP_MACROS_H_
#define _ZEBRA_EIGRP_MACROS_H_

#define DECLARE_IF_PARAM(T, P) T P; u_char P##__config:1
#define IF_EIGRP_IF_INFO(I) ((struct eigrp_interface *)((I)->info))
#define IF_OIFS(I)  (IF_EIGRP_IF_INFO (I)->eifs)
#define IF_OIFS_PARAMS(I) (IF_EIGRP_IF_INFO (I)->eparams)

#define SET_IF_PARAM(S, P) ((S)->P##__config) = 1
#define IF_DEF_PARAMS(I) (IF_EIGRP_IF_INFO (I)->def_params)

#define UNSET_IF_PARAM(S, P) ((S)->P##__config) = 0

#define EIGRP_IF_PARAM_CONFIGURED(S, P) ((S) && (S)->P##__config)
#define EIGRP_IF_PARAM(O, P)                                                   \
	(EIGRP_IF_PARAM_CONFIGURED((O)->params, P)                             \
		 ? (O)->params->P                                              \
		 : IF_DEF_PARAMS((O)->ifp)->P)


//------------------------------------------------------------------------------------------------------------------------------------

#define EIGRP_IF_STRING_MAXLEN  40
#define IF_NAME(I)      eigrp_if_name_string ((I))

//--------------------------------------------------------------------------

/* Topology Macros */


/* FSM macros*/
#define EIGRP_FSM_EVENT_SCHEDULE(I, E)                                         \
	thread_add_event(master, eigrp_fsm_event, (I), (E))

#endif /* _ZEBRA_EIGRP_MACROS_H_ */
