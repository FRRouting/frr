/* FIFO common header.
 * Copyright (C) 2015 Kunihiro Ishiguro
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __LIB_FIFO_H__
#define __LIB_FIFO_H__

/* FIFO -- first in first out structure and macros.  */
struct fifo {
	struct fifo *next;
	struct fifo *prev;
};

#define FIFO_INIT(F)                                                           \
	do {                                                                   \
		struct fifo *Xfifo = (struct fifo *)(F);                       \
		Xfifo->next = Xfifo->prev = Xfifo;                             \
	} while (0)

#define FIFO_ADD(F, N)                                                         \
	do {                                                                   \
		struct fifo *Xfifo = (struct fifo *)(F);                       \
		struct fifo *Xnode = (struct fifo *)(N);                       \
		Xnode->next = Xfifo;                                           \
		Xnode->prev = Xfifo->prev;                                     \
		Xfifo->prev = Xfifo->prev->next = Xnode;                       \
	} while (0)

#define FIFO_DEL(N)                                                            \
	do {                                                                   \
		struct fifo *Xnode = (struct fifo *)(N);                       \
		Xnode->prev->next = Xnode->next;                               \
		Xnode->next->prev = Xnode->prev;                               \
	} while (0)

#define FIFO_HEAD(F)                                                           \
	((((struct fifo *)(F))->next == (struct fifo *)(F)) ? NULL : (F)->next)

#define FIFO_EMPTY(F) (((struct fifo *)(F))->next == (struct fifo *)(F))

#define FIFO_TOP(F) (FIFO_EMPTY(F) ? NULL : ((struct fifo *)(F))->next)

#endif /* __LIB_FIFO_H__ */
