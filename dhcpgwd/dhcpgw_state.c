// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DHCP gateway related functions
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */

#include "dhcpgwd/dhcpgw_state.h"

#include <sys/stat.h>

#include "lib/config_paths.h"

static void get_path_to_if_state_file(const char *ifname, char *path, size_t size);

static void get_path_to_if_state_file(const char *ifname, char *path, size_t size)
{
	strlcpy(path, DHCPGW_STATE_PATH "/", size);
	strlcat(path, ifname, size);
}

/* Partial copy from frr_mkdir */
static int dhcpgw_mkdir(const char *path)
{
	int ret;

	ret = mkdir(path, 0755);

	if (ret != 0) {
		/* if EEXIST, return without touching the permissions,
		 * so user-set custom permissions are left in place
		 */
		if (errno == EEXIST)
			return 0;

		fprintf(stderr, "Failed to mkdir \"%s\": %s", path, strerror(errno));
		return -1;
	}
	return 0;
}

int dhcpgw_state_save(const char *ifname, bool up, int af, const union g_addr *ip_addr)
{
	char path[MAXPATHLEN];
	char ip_str[INET6_ADDRSTRLEN];

	get_path_to_if_state_file(ifname, path, sizeof(path));

	if (!up) { /*down*/
		if (access(path, F_OK) == 0) {
			if (remove(path) == -1) {
				fprintf(stderr, "Couldn't remove file %s, error: %s\n", path,
					strerror(errno));
				return -errno;
			}
		}
	} else { /*up*/
		if (!inet_ntop(af, ip_addr, ip_str, sizeof(ip_str))) {
			fprintf(stderr, "Couldn't convert provided ip to string: %s\n",
				strerror(errno));
			return -errno;
		}

		if (dhcpgw_mkdir(DHCPGW_STATE_PATH)) {
			fprintf(stderr, "Couldn't create directory %s, error: %s\n",
				DHCPGW_STATE_PATH, strerror(errno));
			return -errno;
		}
		FILE *fd = fopen(path, "w");

		if (!fd) {
			fprintf(stderr, "Couldn't open file %s for writing, error: %s\n", path,
				strerror(errno));
			return -errno;
		}
		if (fputs(ip_str, fd) == EOF) {
			fprintf(stderr, "Couldn't write '%s' to file '%s', error: %s\n", ip_str,
				path, strerror(errno));
			fclose(fd);
			return -errno;
		}
		fclose(fd);
	}

	return 0;
}

int dhcpgw_state_read(const char *ifname, bool *up, int *af, union g_addr *ip_addr)
{
	char path[MAXPATHLEN];
	char ip_str[INET6_ADDRSTRLEN];

	get_path_to_if_state_file(ifname, path, sizeof(path));

	/* no state file - no data, assume DHCP interface is down */
	if (access(path, F_OK) != 0) {
		*up = false;
		return 0;
	}

	FILE *fd = fopen(path, "r");

	if (!fd) {
		zlog_warn("%s: couldn't open file %s for reading, error: %s", __func__, path,
			  strerror(errno));
		return -errno;
	}

	if (!fgets(ip_str, sizeof(ip_str), fd)) {
		zlog_warn("%s: couldn't read data from file %s, error: %s", __func__, path,
			  strerror(errno));
		fclose(fd);
		return -errno;
	}
	fclose(fd);

	/* Try IPv4, if not - IPv6 */
	if (inet_pton(AF_INET, ip_str, ip_addr) == 1) {
		*af = AF_INET;
	} else if (inet_pton(AF_INET6, ip_str, ip_addr) == 1) {
		*af = AF_INET6;
	} else {
		*up = false;
		zlog_warn("%s: couldn't parse IP address: '%s'", __func__, ip_str);
		return 1;
	}

	*up = true;
	return 0;
}
