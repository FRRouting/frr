/*
 * ipforward value get function for solaris.
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#include <zebra.h>

#ifdef SUNOS_5

#include "log.h"
#include "prefix.h"
#include "lib_errors.h"

#include "privs.h"
#include "zebra/ipforward.h"
#include "zebra/zebra_errors.h"

/*
** Solaris should define IP_DEV_NAME in <inet/ip.h>, but we'll save
** configure.in changes for another day.  We can use the same device
** for both IPv4 and IPv6.
*/
/* #include <inet/ip.h> */
#ifndef IP_DEV_NAME
#define IP_DEV_NAME "/dev/ip"
#endif


extern struct zebra_privs_t zserv_privs;

/* This is a limited ndd style function that operates one integer
** value only.  Errors return -1. ND_SET commands return 0 on
** success. ND_GET commands return the value on success (which could
** be -1 and be confused for an error).  The parameter is the string
** name of the parameter being referenced.
*/

static int solaris_nd(const int cmd, const char *parameter, const int value)
{
#define ND_BUFFER_SIZE 1024
	int fd;
	char nd_buf[ND_BUFFER_SIZE];
	struct strioctl strioctl;
	const char *device = IP_DEV_NAME;
	int retval;
	memset(nd_buf, '\0', ND_BUFFER_SIZE);
	/*
	** ND_SET takes a NULL delimited list of strings further terminated
	** buy a NULL.  ND_GET returns a list in a similar layout, although
	** here we only use the first result.
	*/
	if (cmd == ND_SET)
		snprintf(nd_buf, ND_BUFFER_SIZE, "%s%c%d%c", parameter, '\0',
			 value, '\0');
	else if (cmd == ND_GET)
		snprintf(nd_buf, ND_BUFFER_SIZE, "%s", parameter);
	else {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "internal error - inappropriate command given to "
			     "solaris_nd()%s:%d",
			     __FILE__, __LINE__);
		return -1;
	}

	strioctl.ic_cmd = cmd;
	strioctl.ic_timout = 0;
	strioctl.ic_len = ND_BUFFER_SIZE;
	strioctl.ic_dp = nd_buf;

	frr_with_privs(&zserv_privs) {
		if ((fd = open(device, O_RDWR)) < 0) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "failed to open device %s - %s", device,
				     safe_strerror(errno));
			return -1;
		}
		if (ioctl(fd, I_STR, &strioctl) < 0) {
			close(fd);
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "ioctl I_STR failed on device %s - %s",
				     device, safe_strerror(errno));
			return -1;
		}
		close(fd);
	}

	if (cmd == ND_GET) {
		errno = 0;
		retval = atoi(nd_buf);
		if (errno) {
			zlog_debug(
				"failed to convert returned value to integer - %s",
				safe_strerror(errno));
			retval = -1;
		}
	} else {
		retval = 0;
	}
	return retval;
}

static int solaris_nd_set(const char *parameter, const int value)
{
	return solaris_nd(ND_SET, parameter, value);
}
static int solaris_nd_get(const char *parameter)
{
	return solaris_nd(ND_GET, parameter, 0);
}
int ipforward(void)
{
	return solaris_nd_get("ip_forwarding");
}

int ipforward_on(void)
{
	(void)solaris_nd_set("ip_forwarding", 1);
	return ipforward();
}

int ipforward_off(void)
{
	(void)solaris_nd_set("ip_forwarding", 0);
	return ipforward();
}
int ipforward_ipv6(void)
{
	return solaris_nd_get("ip6_forwarding");
}
int ipforward_ipv6_on(void)
{
	(void)solaris_nd_set("ip6_forwarding", 1);
	return ipforward_ipv6();
}
int ipforward_ipv6_off(void)
{
	(void)solaris_nd_set("ip6_forwarding", 0);
	return ipforward_ipv6();
}

#endif /* SUNOS_5 */
