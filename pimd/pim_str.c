// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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
