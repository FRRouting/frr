/*
 * This is an implementation of MLAG Functionality
 *
 * Module name: Zebra MLAG
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
#ifndef __ZEBRA_MLAG_PRIVATE_H__
#define __ZEBRA_MLAG_PRIVATE_H__


/*
 * all the platform specific API's
 */

int zebra_mlag_private_open_channel(void);
int zebra_mlag_private_close_channel(void);
void zebra_mlag_private_monitor_state(void);
int zebra_mlag_private_write_data(uint8_t *data, uint32_t len);
void zebra_mlag_private_cleanup_data(void);
#endif
