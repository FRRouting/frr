/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "log.h"

#include "pim_str.h"

void pim_addr_dump(const char *onfail, struct prefix *p, char *buf,
		   int buf_size)
{
	int save_errno = errno;

	if (!inet_ntop(p->family, &p->u.prefix, buf, buf_size)) {
		zlog_warn("pim_addr_dump: inet_ntop(buf_size=%d): errno=%d: %s",
			  buf_size, errno, safe_strerror(errno));
		if (onfail)
			snprintf(buf, buf_size, "%s", onfail);
	}

	errno = save_errno;
}
