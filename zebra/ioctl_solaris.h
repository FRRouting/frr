/*
 * Interface looking up by ioctl () on Solaris.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _ZEBRA_IF_IOCTL_SOLARIS_H
#define _ZEBRA_IF_IOCTL_SOLARIS_H

void lifreq_set_name(struct lifreq *, const char *);
int if_get_flags_direct(const char *, uint64_t *, unsigned int af);

#endif /* _ZEBRA_IF_IOCTL_SOLARIS_H */
