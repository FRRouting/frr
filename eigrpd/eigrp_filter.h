/*
 * EIGRP Filter Functions.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
 *
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef EIGRPD_EIGRP_FILTER_H_
#define EIGRPD_EIGRP_FILTER_H_

extern void eigrp_distribute_update (struct distribute *);
extern void eigrp_distribute_update_interface (struct interface *);
extern void eigrp_distribute_update_all (struct prefix_list *);
extern void eigrp_distribute_update_all_wrapper(struct access_list *);
extern int eigrp_distribute_timer_process (struct thread *);
extern int eigrp_distribute_timer_interface (struct thread *);

#endif /* EIGRPD_EIGRP_FILTER_H_ */
