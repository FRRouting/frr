// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Johan Linder */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <zebra.h>
#include <sys/socket.h>

#include "bfd.h"
#include "buffer.h"
#include "frrevent.h"
#include "log.h"
#include "stream.h"
#include "zclient.h"

struct observed_state {
	unsigned int calls;
	unsigned int failures;
	struct bfd_session_status last;
};

struct session_key {
	int family;
	struct in6_addr src;
	struct in6_addr dst;
	const char *interface;
	vrf_id_t vrf_id;
};

static struct event_loop *master;
static struct zclient client;
static int receiver;

static void status_update(struct bfd_session_params *session,
			  const struct bfd_session_status *status, void *arg)
{
	struct observed_state *observed = arg;

	observed->calls++;
	observed->last = *status;
	if (status->previous_state == BSS_UP && status->state == BSS_DOWN)
		observed->failures++;
}

static void expect_command(int command, const struct session_key *key)
{
	uint8_t bytes[1024];
	uint16_t length;
	struct stream *message;
	struct zmsghdr header;
	size_t address_length;
	uint8_t address[sizeof(struct in6_addr)];

	assert(recv(receiver, bytes, 2, MSG_WAITALL) == 2);
	memcpy(&length, bytes, sizeof(length));
	length = ntohs(length);
	assert(length >= ZEBRA_HEADER_SIZE && length <= sizeof(bytes));
	assert(recv(receiver, bytes + 2, length - 2, MSG_WAITALL) == length - 2);
	message = stream_new(length);
	stream_put(message, bytes, length);
	assert(zapi_parse_header(message, &header));
	assert(header.command == command);
	if (!key) {
		stream_free(message);
		return;
	}
	assert(header.vrf_id == key->vrf_id);
	stream_getl(message); /* client PID */
	assert(stream_getw(message) == key->family);
	address_length = key->family == AF_INET ? 4 : 16;
	stream_get(address, message, address_length);
	assert(memcmp(address, &key->dst, address_length) == 0);
	stream_getl(message);		   /* minimum receive interval */
	stream_getl(message);		   /* minimum transmit interval */
	stream_getc(message);		   /* detection multiplier */
	assert(stream_getc(message) == 0); /* single hop */
	assert(stream_getw(message) == key->family);
	stream_get(address, message, address_length);
	assert(memcmp(address, &key->src, address_length) == 0);
	stream_getc(message); /* hop count */
	length = stream_getc(message);
	assert(length == strlen(key->interface));
	stream_get(address, message, length);
	assert(memcmp(address, key->interface, length) == 0);
	stream_free(message);
}

static void expect_no_command(void)
{
	uint8_t byte;

	assert(recv(receiver, &byte, 1, MSG_DONTWAIT) == -1);
	assert(errno == EAGAIN || errno == EWOULDBLOCK);
}

static void install(struct bfd_session_params *session,
		    const struct session_key *key, int command)
{
	struct event event;

	bfd_sess_install(session);
	assert(event_fetch(master, &event));
	event_call(&event);
	expect_command(command, key);
}

static void notify(const struct session_key *key, int state)
{
	struct stream *message = client.ibuf;
	size_t address_length = key->family == AF_INET ? 4 : 16;

	stream_reset(message);
	stream_putl(message, 0); /* no interface index in this notification */
	stream_putc(message, key->family);
	stream_put(message, &key->dst, address_length);
	stream_putc(message, address_length * 8);
	stream_putl(message, state);
	stream_putc(message, key->family);
	stream_put(message, &key->src, address_length);
	stream_putc(message, address_length * 8);
	stream_putc(message, 0); /* remote control-plane-independent bit */
	stream_putc(message, 0); /* BFD name */
	assert(zclient_bfd_session_update(ZEBRA_INTERFACE_BFD_DEST_UPDATE,
					  &client, stream_get_endp(message),
					  key->vrf_id) == 0);
}

static void set_addresses(struct bfd_session_params *session,
			  const struct session_key *key)
{
	if (key->family == AF_INET)
		bfd_sess_set_ipv4_addrs(session,
					(const struct in_addr *)&key->src,
					(const struct in_addr *)&key->dst);
	else
		bfd_sess_set_ipv6_addrs(session, &key->src, &key->dst);
}

static void expect_transition(struct observed_state *observed,
			      enum bfd_session_state previous,
			      enum bfd_session_state current)
{
	assertf(observed->last.previous_state == previous &&
			observed->last.state == current,
		"expected callback %s -> %s, received %s -> %s",
		bfd_get_status_str(previous), bfd_get_status_str(current),
		bfd_get_status_str(observed->last.previous_state),
		bfd_get_status_str(observed->last.state));
}

static void exercise_family(int family)
{
	struct observed_state observed = {};
	struct session_key key = {
		.family = family,
		.interface = "test0",
		.vrf_id = VRF_DEFAULT,
	};
	struct bfd_session_params *session = bfd_sess_new(status_update,
							  &observed);
	unsigned int calls;

	assert(inet_pton(family, family == AF_INET ? "192.0.2.2" : "2001:db8::2",
			 &key.dst) == 1);
	set_addresses(session, &key);
	bfd_sess_set_interface(session, key.interface);
	install(session, &key, ZEBRA_BFD_DEST_REGISTER);
	notify(&key, BSS_DOWN);
	assert(observed.calls == 1 && observed.last.state == BSS_DOWN);
	assert(observed.last.previous_state != BSS_UP);
	notify(&key, BSS_UP);
	expect_transition(&observed, BSS_DOWN, BSS_UP);

	/* Identical keys and non-key settings preserve the live session. */
	calls = observed.calls;
	set_addresses(session, &key);
	bfd_sess_set_interface(session, key.interface);
	bfd_sess_set_vrf(session, key.vrf_id);
	bfd_sess_set_hop_count(session, 1);
	expect_no_command();
	bfd_sess_set_timers(session, 3, 1000, 1000);
	bfd_sess_set_profile(session, "fast");
	install(session, &key, ZEBRA_BFD_DEST_UPDATE);
	notify(&key, BSS_UP);
	assert(observed.calls == calls);
	assert(bfd_sess_status(session) == BSS_UP);

	for (unsigned int change = 0; change < 4; change++) {
		struct session_key old_key = key;

		if (change == 0) {
			assert(inet_pton(family,
					 family == AF_INET ? "192.0.2.1"
							   : "2001:db8::1",
					 &key.src) == 1);
			set_addresses(session, &key);
		} else if (change == 1) {
			assert(inet_pton(family,
					 family == AF_INET ? "192.0.2.3"
							   : "2001:db8::3",
					 &key.dst) == 1);
			set_addresses(session, &key);
		} else if (change == 2) {
			key.interface = "test1";
			bfd_sess_set_interface(session, key.interface);
		} else {
			key.vrf_id = 10;
			bfd_sess_set_vrf(session, key.vrf_id);
		}
		expect_command(ZEBRA_BFD_DEST_DEREGISTER, &old_key);
		install(session, &key, ZEBRA_BFD_DEST_REGISTER);
		calls = observed.calls;
		notify(&key, BSS_DOWN);
		assert(observed.calls == calls + 1);
		expect_transition(&observed, BSS_UNKNOWN, BSS_DOWN);
		assert(observed.failures == change);
		/* A replacement that never comes Up reports no failure transition. */
		notify(&key, BSS_DOWN);
		assert(observed.calls == calls + 1);
		notify(&key, BSS_UP);
		expect_transition(&observed, BSS_DOWN, BSS_UP);
		/* A real failure of the replacement must still reach the protocol. */
		notify(&key, BSS_DOWN);
		expect_transition(&observed, BSS_UP, BSS_DOWN);
		assert(observed.failures == change + 1);
		notify(&key, BSS_UP);
	}

	/* Changing the key after an uninstall also starts a new history. */
	bfd_sess_uninstall(session);
	struct event event;

	assert(event_fetch(master, &event));
	event_call(&event);
	expect_command(ZEBRA_BFD_DEST_DEREGISTER, &key);
	key.interface = "test2";
	bfd_sess_set_interface(session, key.interface);
	expect_no_command();
	install(session, &key, ZEBRA_BFD_DEST_REGISTER);
	notify(&key, BSS_DOWN);
	expect_transition(&observed, BSS_UNKNOWN, BSS_DOWN);
	assert(observed.failures == 4);
	bfd_sess_free(&session);
	expect_command(ZEBRA_BFD_DEST_DEREGISTER, &key);
	printf("IPv%d BFD key replacement and failure callbacks passed.\n",
	       family == AF_INET ? 4 : 6);
}

int main(void)
{
	int sockets[2];
	struct timeval timeout = { .tv_sec = 2 };

	zlog_aux_init("test_bfd_session", LOG_ERR);
	master = event_master_create("bfd_session");
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	receiver = sockets[1];
	assert(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout,
			  sizeof(timeout)) == 0);
	client.master = master;
	client.sock = sockets[0];
	client.ibuf = stream_new(1024);
	client.obuf = stream_new(1024);
	client.wb = buffer_new(0);
	bfd_protocol_integration_init(&client, master);
	expect_command(ZEBRA_BFD_CLIENT_REGISTER, NULL);
	exercise_family(AF_INET);
	exercise_family(AF_INET6);
	stream_free(client.ibuf);
	stream_free(client.obuf);
	buffer_free(client.wb);
	close(sockets[0]);
	close(sockets[1]);
	event_master_free(master);
	return 0;
}
