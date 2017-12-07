/*
 * Copyright (C) 2016 by Open Source Routing.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#ifndef _LDP_DEBUG_H_
#define	_LDP_DEBUG_H_

struct ldp_debug {
	int	 hello;
#define LDP_DEBUG_HELLO_RECV	0x01
#define LDP_DEBUG_HELLO_SEND	0x02

	int	 errors;
#define LDP_DEBUG_ERRORS	0x01

	int	 event;
#define LDP_DEBUG_EVENT		0x01

	int	 labels;
#define LDP_DEBUG_LABELS	0x01

	int	 msg;
#define LDP_DEBUG_MSG_RECV	0x01
#define LDP_DEBUG_MSG_RECV_ALL	0x02
#define LDP_DEBUG_MSG_SEND	0x04
#define LDP_DEBUG_MSG_SEND_ALL	0x08

	int	 zebra;
#define LDP_DEBUG_ZEBRA		0x01
};
extern struct ldp_debug	 conf_ldp_debug;
extern struct ldp_debug	 ldp_debug;

#define CONF_DEBUG_ON(a, b)	(conf_ldp_debug.a |= (b))
#define CONF_DEBUG_OFF(a, b)	(conf_ldp_debug.a &= ~(b))

#define TERM_DEBUG_ON(a, b)	(ldp_debug.a |= (b))
#define TERM_DEBUG_OFF(a, b)	(ldp_debug.a &= ~(b))

#define DEBUG_ON(a, b)			\
    do {				\
	if (vty->node == CONFIG_NODE) { \
		CONF_DEBUG_ON(a, b);	\
		TERM_DEBUG_ON(a, b);	\
	} else				\
		TERM_DEBUG_ON(a, b);	\
    } while (0)
#define DEBUG_OFF(a, b)			\
    do {				\
	CONF_DEBUG_OFF(a, b);		\
	TERM_DEBUG_OFF(a, b);		\
    } while (0)

#define LDP_DEBUG(a, b)		(ldp_debug.a & b)
#define CONF_LDP_DEBUG(a, b)    (conf_ldp_debug.a & b)

#define		 debug_hello_recv(emsg, ...)				\
do {									\
	if (LDP_DEBUG(hello, LDP_DEBUG_HELLO_RECV))			\
		log_debug("discovery[recv]: " emsg, __VA_ARGS__);	\
} while (0)

#define		 debug_hello_send(emsg, ...)				\
do {									\
	if (LDP_DEBUG(hello, LDP_DEBUG_HELLO_SEND))			\
		log_debug("discovery[send]: " emsg, __VA_ARGS__);	\
} while (0)

#define		 debug_err(emsg, ...)					\
do {									\
	if (LDP_DEBUG(errors, LDP_DEBUG_ERRORS))			\
		log_debug("error: " emsg, __VA_ARGS__);			\
} while (0)

#define		 debug_evt(emsg, ...)					\
do {									\
	if (LDP_DEBUG(event, LDP_DEBUG_EVENT))				\
		log_debug("event: " emsg, __VA_ARGS__);			\
} while (0)

#define		 debug_labels(emsg, ...)				\
do {									\
	if (LDP_DEBUG(labels, LDP_DEBUG_LABELS))			\
		log_debug("labels: " emsg, __VA_ARGS__);		\
} while (0)

#define		 debug_msg_recv(emsg, ...)				\
do {									\
	if (LDP_DEBUG(msg, LDP_DEBUG_MSG_RECV))				\
		log_debug("msg[in]: " emsg, __VA_ARGS__);		\
} while (0)

#define		 debug_msg_send(emsg, ...)				\
do {									\
	if (LDP_DEBUG(msg, LDP_DEBUG_MSG_SEND))				\
		log_debug("msg[out]: " emsg, __VA_ARGS__);		\
} while (0)

#define		 debug_msg(out, emsg, ...)				\
do {									\
	if (out)							\
		debug_msg_send(emsg, __VA_ARGS__);			\
	else								\
		debug_msg_recv(emsg, __VA_ARGS__);			\
} while (0)

#define		 debug_kalive_recv(emsg, ...)				\
do {									\
	if (LDP_DEBUG(msg, LDP_DEBUG_MSG_RECV_ALL))			\
		log_debug("kalive[in]: " emsg, __VA_ARGS__);		\
} while (0)

#define		 debug_kalive_send(emsg, ...)				\
do {									\
	if (LDP_DEBUG(msg, LDP_DEBUG_MSG_SEND_ALL))			\
		log_debug("kalive[out]: " emsg, __VA_ARGS__);		\
} while (0)

#define		 debug_zebra_in(emsg, ...)				\
do {									\
	if (LDP_DEBUG(zebra, LDP_DEBUG_ZEBRA))				\
		log_debug("zebra[in]: " emsg, __VA_ARGS__);		\
} while (0)

#define		 debug_zebra_out(emsg, ...)				\
do {									\
	if (LDP_DEBUG(zebra, LDP_DEBUG_ZEBRA))				\
		log_debug("zebra[out]: " emsg, __VA_ARGS__);		\
} while (0)

#endif /* _LDP_DEBUG_H_ */
