/*
 * Network library header.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_NETWORK_H
#define _ZEBRA_NETWORK_H

/* Both readn and writen are deprecated and will be removed.  They are not
   suitable for use with non-blocking file descriptors.
 */
extern int readn(int, uint8_t *, int);
extern int writen(int, const uint8_t *, int);

/* Set the file descriptor to use non-blocking I/O.  Returns 0 for success,
   -1 on error. */
extern int set_nonblocking(int fd);

extern int set_cloexec(int fd);

/* Does the I/O error indicate that the operation should be retried later? */
#define ERRNO_IO_RETRY(EN)                                                     \
	(((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

extern float htonf(float);
extern float ntohf(float);

#endif /* _ZEBRA_NETWORK_H */
