/*
 * ldp - vrf code
 * Copyright (C) 2019 VMware Inc.
 *               Kishore Aramalla
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

#ifndef _ZEBRA_LDP_ZEBRA_H
#define _ZEBRA_LDP_ZEBRA_H

void ldp_zebra_init(struct thread_master *);
void ldp_zebra_vrf_register(struct vrf *vrf);
void ldp_zebra_vrf_unregister(struct vrf *vrf);

#endif /* _ZEBRA_ISIS_ZEBRA_H */
