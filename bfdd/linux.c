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
int ptm_bfd_fetch_ifindex(const char *ifname)
{
	struct ifreq ifr;

	if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name))
	    > sizeof(ifr.ifr_name))
		log_error("interface-to-index: name truncated ('%s' -> '%s')",
			  ifr.ifr_name, ifname);

	if (ioctl(bglobal.bg_shop, SIOCGIFINDEX, &ifr) == -1) {
		log_error("interface-to-index: %s translation failed: %s",
			  ifname, strerror(errno));
		return -1;
	}

	return ifr.ifr_ifindex;
}

void ptm_bfd_fetch_local_mac(const char *ifname, uint8_t *mac)
{
	struct ifreq ifr;

	if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name))
	    > sizeof(ifr.ifr_name))
		log_error("interface-mac: name truncated ('%s' -> '%s')",
			  ifr.ifr_name, ifname);

	if (ioctl(bglobal.bg_shop, SIOCGIFHWADDR, &ifr) == -1) {
		log_error("interface-mac: %s MAC retrieval failed: %s", ifname,
			  strerror(errno));
		return;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHERNET_ADDRESS_LENGTH);
}


/* Was _fetch_portname_from_ifindex() */
void fetch_portname_from_ifindex(int ifindex, char *ifname, size_t ifnamelen)
{
	struct ifreq ifr;

	ifname[0] = 0;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;

	if (ioctl(bglobal.bg_shop, SIOCGIFNAME, &ifr) == -1) {
		log_error("index-to-interface: index %d failure: %s", ifindex,
			  strerror(errno));
		return;
	}

	if (strlcpy(ifname, ifr.ifr_name, ifnamelen) >= ifnamelen)
		log_debug("index-to-interface: name truncated '%s' -> '%s'",
			  ifr.ifr_name, ifname);
}

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
