/*
 * *BSD specific code
 *
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
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

#include <zebra.h>

#ifdef BFD_BSD

#include <net/if.h>
#include <net/if_types.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <ifaddrs.h>

#include "bfd.h"

/*
 * Definitions.
 */
int bp_bind_dev(int sd, const char *dev)
{
	/*
	 * *BSDs don't support `SO_BINDTODEVICE`, instead you must
	 * manually specify the main address of the interface or use
	 * BPF on the socket descriptor.
	 */
	return 0;
}

#endif /* BFD_BSD */
