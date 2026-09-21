// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * network_address_parse() unit test
 * Copyright (C) 2026 Rafael Zalamena
 */

#include <zebra.h>

#include <sys/un.h>

#include "lib/network.h"

/*
 * Keep the output free of platform dependent values (`AF_*` numbers,
 * `sizeof(struct sockaddr_un)`, interface indexes) so the reference output
 * matches everywhere.
 */
static void test(const char *address_string, uint16_t default_port)
{
	struct network_address address = {};
	char buf[INET6_ADDRSTRLEN];

	printf("'%s' (default port %u)\n", address_string, default_port);

	if (!network_address_parse(address_string, &address, default_port)) {
		printf("  error: '%s'\n", address.error);
		return;
	}

	printf("  mode: %s\n", address.listen ? "listen" : "connect");

	switch (address.address.ss_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)&address.address;

		printf("  type: ipv4\n");
		printf("  address: %s\n", inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)));
		printf("  port: %u\n", ntohs(sin->sin_port));
		assert(address.address_size == sizeof(*sin));
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&address.address;

		printf("  type: ipv6\n");
		printf("  address: %s\n", inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)));
		printf("  port: %u\n", ntohs(sin6->sin6_port));
		printf("  scope: %s\n", sin6->sin6_scope_id ? "set" : "unset");
		assert(address.address_size == sizeof(*sin6));
		break;
	}
	case AF_UNIX: {
		struct sockaddr_un *sunp = (struct sockaddr_un *)&address.address;

		printf("  type: unix\n");
		printf("  path: %s\n", sunp->sun_path);
		assert(address.address_size == sizeof(*sunp));
		break;
	}
	default:
		printf("  unexpected family\n");
		break;
	}
}

/*
 * `sun_path` is not the same size on every platform, so exercise the length
 * boundary relative to it and print only the outcome.
 */
static void test_unix_path_length(size_t length)
{
	struct network_address address = {};
	struct sockaddr_un sun;
	char address_string[sizeof(sun.sun_path) + 128];

	assert(length < sizeof(address_string) - sizeof("unix:"));

	strlcpy(address_string, "unix:", sizeof(address_string));
	memset(address_string + strlen("unix:"), 'a', length);
	address_string[strlen("unix:") + length] = 0;

	printf("unix path of sizeof(sun_path)%+d bytes: %s\n",
	       (int)length - (int)sizeof(sun.sun_path),
	       network_address_parse(address_string, &address, 4444) ? "accepted" : "rejected");
}

int main(int argc, char *argv[])
{
	struct sockaddr_un sun;

	printf("== IPv4 ==\n");
	test("ipv4:127.0.0.1", 4444);
	test("ipv4:127.0.0.1:8080", 4444);
	test("ipv4c:127.0.0.1:8080", 4444);
	test("ipv4:0.0.0.0:1", 4444);
	test("ipv4:255.255.255.255:65535", 4444);

	printf("\n== IPv6 ==\n");
	test("ipv6:[::1]", 4444);
	test("ipv6:[::1]:8080", 4444);
	test("ipv6c:[::1]:8080", 4444);
	test("ipv6:[2001:db8::1]:179", 4444);
	test("ipv6:[::]:1", 4444);

	printf("\n== unix ==\n");
	test("unix:/var/run/frr/test.sock", 4444);
	test("unixc:/var/run/frr/test.sock", 4444);
	/* The port is meaningless for unix sockets: ':' is part of the path. */
	test("unix:/var/run/frr/test.sock:8080", 4444);

	printf("\n== invalid type ==\n");
	test("", 4444);
	test("nocolon", 4444);
	test("IPV4:127.0.0.1", 4444);
	test("bogus:127.0.0.1", 4444);
	test(":127.0.0.1", 4444);
	test("ipv4:", 4444);
	test("ipv6:", 4444);
	test("unix:", 4444);

	printf("\n== invalid address ==\n");
	test("ipv4:256.0.0.1", 4444);
	test("ipv4:not-an-address", 4444);
	test("ipv6:[::g]", 4444);
	test("ipv6:::1", 4444);
	test("ipv6:[::1", 4444);
	test("ipv6:[]", 4444);

	printf("\n== trailing garbage after ']' ==\n");
	test("ipv6:[::1]junk", 4444);
	test("ipv6:[::1]junk:80", 4444);
	test("ipv6:[::1]:80:90", 4444);

	printf("\n== invalid port ==\n");
	test("ipv4:127.0.0.1:0", 4444);
	test("ipv4:127.0.0.1:65536", 4444);
	test("ipv4:127.0.0.1:-1", 4444);
	test("ipv4:127.0.0.1:+80", 4444);
	test("ipv4:127.0.0.1: 80", 4444);
	test("ipv4:127.0.0.1:80x", 4444);
	test("ipv4:127.0.0.1:", 4444);
	test("ipv4:127.0.0.1:99999999999999999999", 4444);
	test("ipv6:[::1]:0", 4444);
	test("ipv6:[::1]:65536", 4444);

	printf("\n== IPv6 scope ==\n");
	test("ipv6:[fe80::1%frr-no-such-if]:1234", 4444);

	printf("\n== unix path length boundary ==\n");
	/* The longest path that still leaves room for the NUL terminator. */
	test_unix_path_length(sizeof(sun.sun_path) - 1);
	/* One byte too long: the NUL terminator no longer fits. */
	test_unix_path_length(sizeof(sun.sun_path));
	test_unix_path_length(sizeof(sun.sun_path) + 64);

	return 0;
}
