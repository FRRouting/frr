/* TCP Authentication Option using FRR keychains
 *
 * Copyright (C) 2021 Leonard Crestez <cdleonard@gmail.com>
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include "log.h"
#include "vty.h"
#include "json.h"
#include "tcp_authopt.h"

#ifdef __linux__
#define HAVE_LINUX_TCP_AUTHOPT
#endif

#ifdef HAVE_LINUX_TCP_AUTHOPT
#include <linux/tcp_authopt.h>

static void
tcp_authopt_key_init_binding_from_zebra(struct tcp_authopt_key *keyopt,
					union sockunion *su, struct key *key)
{
	keyopt->send_id = key->tcp_authopt_send_id;
	keyopt->recv_id = key->tcp_authopt_recv_id;
	if (su && su->sa.sa_family == AF_INET) {
		memcpy(&keyopt->addr, &su->sin, sizeof(su->sin));
		keyopt->flags |= TCP_AUTHOPT_KEY_ADDR_BIND;
	} else if (su && su->sa.sa_family == AF_INET6) {
		memcpy(&keyopt->addr, &su->sin6, sizeof(su->sin6));
		keyopt->flags |= TCP_AUTHOPT_KEY_ADDR_BIND;
	} else {
		keyopt->addr.ss_family = 0;
	}
}

static int tcp_authopt_keychain_add(int sock, union sockunion *su,
				    struct keychain *keychain)
{
	struct key *key;
	struct listnode *node;
	struct tcp_authopt_key keyopt;
	time_t now;
	size_t keylen;
	int added_keys = 0;

	now = time(NULL);

	zlog_debug("add sock=%d addr=%pSU keychain=%s", sock, su,
		   keychain->name);
	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (!key->tcp_authopt_enabled)
			continue;

		/* Linux implementation doesn't allow marking keys as expired so
		 * only add those that are valid.
		 */
		if (!key_valid_for_accept(key, now))
			continue;
		if (!key_valid_for_accept(key, now))
			continue;

		keylen = strlen(key->string);
		if (keylen > TCP_AUTHOPT_MAXKEYLEN) {
			zlog_err("Key too long, skipped");
			return -1;
		}

		memset(&keyopt, 0, sizeof(keyopt));
		tcp_authopt_key_init_binding_from_zebra(&keyopt, su, key);
		keyopt.keylen = keylen;
		/* Matches because zebra uses linux constants: */
		keyopt.alg = key->tcp_authopt_alg;
		memcpy(&keyopt.key, key->string, keylen);
		zlog_debug(
			"add sock=%d addr=%pSU key index=%d send_id=%d recv_id=%d",
			sock, su, key->index, (int)keyopt.send_id,
			(int)keyopt.recv_id);
		if (setsockopt(sock, IPPROTO_TCP, TCP_AUTHOPT_KEY, &keyopt,
			       sizeof(keyopt))
		    < 0) {
			zlog_warn("setsockopt TCP_AUTHOPT_KEY: %s",
				  safe_strerror(errno));
			return -1;
		}
		added_keys++;
	}
	if (!added_keys) {
		/* Currently kernel accepts everything if no keys are added for
		 * an address. This means that if all keys fail unsigned packets
		 * will be accepted!
		 */
		zlog_warn("No valid tcp_authopt keys added from keychain %s",
			  keychain->name);
		return -1;
	}

	return 0;
}

static int tcp_authopt_keychain_del(int sock, union sockunion *su,
				    struct keychain *keychain)
{
	struct key *key;
	struct listnode *node;
	struct tcp_authopt_key keyopt;
	int ret = 0;

	zlog_debug("del sock=%d addr=%pSU keychain=%s", sock, su,
		   keychain->name);
	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (!key->tcp_authopt_enabled)
			continue;

		keyopt.flags = TCP_AUTHOPT_KEY_DEL;
		tcp_authopt_key_init_binding_from_zebra(&keyopt, su, key);
		if (setsockopt(sock, IPPROTO_TCP, TCP_AUTHOPT_KEY, &keyopt,
			       sizeof(keyopt))
		    < 0) {
			if (errno == ENOENT) {
				zlog_info(
					"setsockopt TCP_AUTHOPT_KEY_DEL ENOENT");
			} else {
				zlog_warn(
					"setsockopt TCP_AUTHOPT_KEY_DEL unexpected error: %s",
					safe_strerror(errno));
				/* keep removing the rest of the keys */
				ret = -1;
			}
		}
	}

	return ret;
}
#else
static int tcp_authopt_keychain_add(int sock, union sockunion *su,
				    struct keychain *keychain)
{
	return -1;
}

static int tcp_authopt_keychain_del(int sock, union sockunion *su,
				    struct keychain *keychain)
{
	return -1;
}
#endif

static void __tcp_authopt_user_set_keychain_name(struct tcp_authopt_user *user,
						 const char *keychain_name)
{
	free(user->keychain_name);
	if (keychain_name)
		user->keychain_name = strdup(keychain_name);
	else
		user->keychain_name = NULL;
}

/**
 * Discard and forget everything.
 * Does not delete keys.
 * Meant for socket closing.
 */
int tcp_authopt_user_reset(struct tcp_authopt_user *user)
{
	user->sock = -1;
	memset(&user->su, 0, sizeof(user->su));
	__tcp_authopt_user_set_keychain_name(user, NULL);
	return 0;
}

/**
 * Change keychain on a socket.
 *
 * Requires tcp_authopt_user_init to specific sock and addr first.
 * Removes old keys and adds new keys.
 */
int tcp_authopt_user_set(struct tcp_authopt_user *user,
			 const char *keychain_name)
{
	struct keychain *keychain;

	if (user->keychain_name && keychain_name
	    && !strcmp(user->keychain_name, keychain_name))
		return 0;
	if (user->keychain_name == NULL && keychain_name == NULL)
		return 0;

	zlog_info("sock=%d addr=%pSU old_keychain_name=%s new_keychain_name=%s",
		  user->sock, &user->su, user->keychain_name ?: "(null)",
		  keychain_name ?: "(null)");

	/* Clear old keys. */
	if (user->keychain_name) {
		keychain = keychain_lookup(user->keychain_name);
		if (keychain && user->sock >= 0)
			tcp_authopt_keychain_del(user->sock, &user->su,
						 keychain);
	}

	__tcp_authopt_user_set_keychain_name(user, keychain_name);
	if (!keychain_name)
		return 0;

	keychain = keychain_lookup(user->keychain_name);
	if (!keychain) {
		zlog_err("no keychain %s", user->keychain_name);
		return -1;
	}
	if (user->sock < 0) {
		zlog_err("invalid sock %d", user->sock);
		return -1;
	}
	return tcp_authopt_keychain_add(user->sock, &user->su, keychain);
}

int tcp_authopt_user_init(struct tcp_authopt_user *user, int sock,
			  union sockunion *su)
{
	if (user->sock == sock && 0 == memcmp(&user->su, su, sizeof(*su)))
		return 0;

	zlog_info("sock=%d addr=%pSU old_keychain_name=%s", sock, su,
		  user->keychain_name);
	tcp_authopt_user_set(user, NULL);
	user->sock = sock;
	user->su = *su;

	return 0;
}

/**
 * Handle socket accept: assumes sock keys were already added and
 * prepares for future updates.
 *
 * Implies reset.
 */
int tcp_authopt_user_init_accept(struct tcp_authopt_user *user, int sock,
				 union sockunion *su, const char *keychain_name)
{
	zlog_info("sock=%d su=%pSU keychain_name=%s", sock, su,
		  user->keychain_name);
	tcp_authopt_user_reset(user);
	__tcp_authopt_user_set_keychain_name(user, keychain_name);
	user->sock = sock;
	user->su = *su;

	return 0;
}

#ifdef HAVE_LINUX_TCP_AUTHOPT
static int get_tcp_authopt(int sock, struct tcp_authopt *opt)
{
	socklen_t optlen = sizeof(opt);

	if (getsockopt(sock, IPPROTO_TCP, TCP_AUTHOPT, opt, &optlen) < 0)
		return -errno;
	else
		return 0;
}

/**
 * Print a line on vty showing current TCP-AO status on one socket FD.
 */
void tcp_authopt_show_sock(struct vty *vty, int sock)
{
	struct tcp_authopt opt;
	int err = 0;

	err = get_tcp_authopt(sock, &opt);
	zlog_debug("sock=%d getsockopt TCP_AUTHOPT err=%d", sock, -err);
	if (err == -ENOPROTOOPT) {
		vty_out(vty, "TCP Authentication Option not Supported\n");
		return;
	}
	if (err == -ENOENT) {
		vty_out(vty, "TCP Authentication Option not Enabled\n");
		return;
	}
	if (err) {
		vty_out(vty,
			"TCP Authentication Option unexpected getsockopt err: %s\n",
			safe_strerror(-err));
		return;
	}
	vty_out(vty,
		"TCP Authentication Option Enabled:"
		" keyid %hhu"
		" rnextkeyid %hhu"
		" recv_keyid %hhu"
		" recv_rnextkeyid %hhu\n",
		opt.send_keyid, opt.send_rnextkeyid, opt.recv_keyid,
		opt.recv_rnextkeyid);
}

/**
 * Show tcp_authopt status as a json object
 */
void tcp_authopt_show_sock_json(struct json_object *json_parent, int sock)
{
	struct tcp_authopt opt;
	struct json_object *jo;
	int err = 0;

	err = get_tcp_authopt(sock, &opt);

	jo = json_object_new_object();
	json_object_object_add(json_parent, "tcp_authopt", jo);

	zlog_debug("sock=%d getsockopt TCP_AUTHOPT err=%d", sock, -err);
	if (err == -ENOPROTOOPT) {
		json_object_string_add(jo, "status", "not supported");
		return;
	}
	if (err == -ENOENT) {
		json_object_string_add(jo, "status", "not enabled");
		return;
	}
	if (err) {
		json_object_string_add(jo, "status", "unknown");
		return;
	}
	json_object_string_add(jo, "status", "enabled");
	json_object_int_add(jo, "send_keyid", opt.send_keyid);
	json_object_int_add(jo, "send_rnextkeyid", opt.send_rnextkeyid);
	json_object_int_add(jo, "recv_keyid", opt.recv_keyid);
	json_object_int_add(jo, "recv_rnextkeyid", opt.recv_rnextkeyid);
}
#else
void tcp_authopt_show_sock(struct vty *vty, int sock)
{
	vty_out(vty, "TCP Authentication Option not Supported\n");
}

void tcp_authopt_show_sock_json(struct json_object *json_parent, int sock)
{
	struct json_object *jo;

	jo = json_object_new_object();
	json_object_object_add(json_parent, "tcp_authopt", jo);
	json_object_string_add(jo, "status", "not supported");
}
#endif
