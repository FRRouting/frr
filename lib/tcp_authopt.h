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
#ifndef _ZEBRA_TCP_AUTHOPT_H
#define _ZEBRA_TCP_AUTHOPT_H

#include "keychain.h"
#include "sockunion.h"

/**
 * struct tcp_authopt_user - Use one keychain on one socket
 */
struct tcp_authopt_user {
	char *keychain_name;
	union sockunion su;
	int sock;
};

int tcp_authopt_user_reset(
		struct tcp_authopt_user *user);
int tcp_authopt_user_init(
		struct tcp_authopt_user *user,
		int sock,
		union sockunion *su);
int tcp_authopt_user_set(
		struct tcp_authopt_user *user,
		const char *keychain_name);
int tcp_authopt_user_init_accept(
		struct tcp_authopt_user *user,
		int sock,
		union sockunion *su,
		const char *keychain_name);
void tcp_authopt_show_sock(struct vty *vty, int sock);
void tcp_authopt_show_sock_json(struct json_object *json_parent, int sock);

#endif /* _ZEBRA_TCP_AUTHOPT_H */
