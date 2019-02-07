/*
 * Linux specific code
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

#ifdef BFD_LINUX

#include "bfd.h"


/*
 * Definitions.
 */
int bp_bind_dev(int sd __attribute__((__unused__)),
		const char *dev __attribute__((__unused__)))
{
	/*
	 * TODO: implement this differently. It is not possible to
	 * SO_BINDTODEVICE after the daemon has dropped its privileges.
	 */
#if 0
	size_t devlen = strlen(dev) + 1;

	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, dev, devlen) == -1) {
		log_warning("%s: setsockopt(SO_BINDTODEVICE, \"%s\"): %s",
			    __func__, dev, strerror(errno));
		return -1;
	}
#endif

	return 0;
}

#endif /* BFD_LINUX */
