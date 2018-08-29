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
int ptm_bfd_fetch_ifindex(const char *ifname)
{
	return if_nametoindex(ifname);
}

void ptm_bfd_fetch_local_mac(const char *ifname, uint8_t *mac)
{
	struct ifaddrs *ifap, *ifa;
	struct if_data *ifi;
	struct sockaddr_dl *sdl;
	size_t maclen;

	/* Always clean the target, zeroed macs mean failure. */
	memset(mac, 0, ETHERNET_ADDRESS_LENGTH);

	if (getifaddrs(&ifap) != 0)
		return;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		/* Find interface with that name. */
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		/* Skip non link addresses. We want the MAC address. */
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		ifi = (struct if_data *)ifa->ifa_data;
		/* Skip non ethernet related data. */
		if (ifi->ifi_type != IFT_ETHER)
			continue;

		if (sdl->sdl_alen != ETHERNET_ADDRESS_LENGTH)
			log_warning("%s:%d mac address length %d (expected %d)",
				    __func__, __LINE__, sdl->sdl_alen,
				    ETHERNET_ADDRESS_LENGTH);

		maclen = (sdl->sdl_alen > ETHERNET_ADDRESS_LENGTH)
				 ? ETHERNET_ADDRESS_LENGTH
				 : sdl->sdl_alen;
		memcpy(mac, LLADDR(sdl), maclen);
		break;
	}

	freeifaddrs(ifap);
}


/* Was _fetch_portname_from_ifindex() */
void fetch_portname_from_ifindex(int ifindex, char *ifname, size_t ifnamelen)
{
	char ifname_tmp[IF_NAMESIZE];

	/* Set ifname to empty to signalize failures. */
	memset(ifname, 0, ifnamelen);

	if (if_indextoname(ifindex, ifname_tmp) == NULL)
		return;

	if (strlcpy(ifname, ifname_tmp, ifnamelen) > ifnamelen)
		log_warning("%s:%d interface name truncated", __func__,
			    __LINE__);
}

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
