/* Zebra PW code
 * Copyright (C) 2016 Volta Networks, Inc.
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

#ifndef ZEBRA_PW_H_
#define ZEBRA_PW_H_

#include <net/if.h>
#include <netinet/in.h>

#include "zclient.h"

#define PW_PROCESS_HOLD_TIME 10
#define PW_MAX_RETRIES 3

DECLARE_HOOK(pw_change, (struct zebra_pw_t * pw), (pw))

void pw_update(int cmd, struct zebra_pw_t *pw);
struct zebra_pw_t *pw_add(void);
void pw_del(struct zebra_pw_t *pw);
void pw_queue_add(struct zebra_pw_t *pw);
void unqueue_pw(struct zebra_pw_t *pw);
void zebra_pw_init(void);

#endif				/* ZEBRA_PW_H_ */
