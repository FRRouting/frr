// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * update-dhcp-gw tool - updates information about
 *      DHCP status, should be called from DHCP client hook
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */
/*
 * Small tool to be called from DHCP clients to save state
 *
 * For this to work the process must have write access to dhcpgw state directory.
 * One of options is for update-dhcp-gw to be owned by frr user and have setuid
 * mode. This is configured by systemd-tmpfiles configured in debian/frr.conf
 *
 * This way everything works even if FRR is started later then DHCP client
 * gets gateway IP.
 */

#include <zebra.h>

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/param.h>

#include "xref.h"

#include "dhcpgwd/dhcpgw_state.h"

char command[MAXPATHLEN];

static void help(const char *command_name);

static void help(const char *command_name)
{
	fprintf(stderr,
		"Usage: %s interface [up IP|down]\n"
		"\te.g. %s eth0 up 10.1.1.1\n",
		command_name, command_name);
}

int main(int argc, char **argv)
{
	if (argc != 3 && argc != 4) {
		help(argv[0]);
		return 1;
	}

	/* From https://www.freedesktop.org/software/systemd/man/latest/systemd.link.html
	 *
	 * Interface names must have a minimum length of 1 character and a maximum
	 * length of 15 characters, and may contain any 7bit ASCII character, with
	 * the exception of control characters, ":", "/" and "%". While "." is an
	 * allowed character, it is recommended to avoid it when naming interfaces
	 * as various tools (such as resolvconf(1)) use it as separator character.
	 * Also, fully numeric interface names are not allowed (in order to avoid
	 * ambiguity with interface specification by numeric indexes), nor are the
	 * special strings ".", "..", "all" and "default".
	 *
	 * TODO should interface names with special symbols be processed properly?
	 */
	const char *ifname = argv[1];
	const char *ip_str = NULL;
	bool up;

	if (!strcmp(argv[2], "up")) {
		if (argc != 4) {
			help(argv[0]);
			return 1;
		}
		ip_str = argv[3];
		up = true;
	} else if (!strcmp(argv[2], "down")) {
		if (argc != 3) {
			help(argv[0]);
			return 1;
		}
		up = false;
	} else {
		help(argv[0]);
		return 1;
	}

	int af = 0;
	union g_addr ip_addr;

	if (up) {
		/* Try IPv4, if not - IPv6 */
		if (inet_pton(AF_INET, ip_str, &ip_addr) == 1) {
			af = AF_INET;
		} else if (inet_pton(AF_INET6, ip_str, &ip_addr) == 1) {
			af = AF_INET6;
		} else {
			fprintf(stderr, "Couldn't parse IP address: '%s'", ip_str);
			return 1;
		}
	}

	int ret = dhcpgw_state_save(ifname, up, af, &ip_addr);

	if (ret) {
		fprintf(stderr, "Failed to save state, exiting\n");
		return ret;
	}

	/* All is ok, time to call 'dhcpgw update' */
	/* Ignore return value - if dchpgwd is not running yet, that is not an error */
	sprintf(command, "vtysh -c 'dhcpgw update %s'", ifname);
	system(command);

	return 0;
}

XREF_SETUP();
