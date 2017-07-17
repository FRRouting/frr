/* AS regular expression routine
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _QUAGGA_BGP_REGEX_H
#define _QUAGGA_BGP_REGEX_H

#include <zebra.h>

#ifdef HAVE_LIBPCREPOSIX
#include <pcreposix.h>
#else
#include <regex.h>
#endif /* HAVE_LIBPCREPOSIX */

extern void bgp_regex_free(regex_t *regex);
extern regex_t *bgp_regcomp(const char *str);
extern int bgp_regexec(regex_t *regex, struct aspath *aspath);

#endif /* _QUAGGA_BGP_REGEX_H */
