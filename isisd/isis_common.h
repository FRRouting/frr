/*
 * IS-IS Rout(e)ing protocol - isis_common.h
 *                             some common data structures
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef ISIS_COMMON_H
#define ISIS_COMMON_H

/*
 * Area Address
 */
struct area_addr {
	uint8_t addr_len;
	uint8_t area_addr[20];
};

struct isis_passwd {
	uint8_t len;
#define ISIS_PASSWD_TYPE_UNUSED   0
#define ISIS_PASSWD_TYPE_CLEARTXT 1
#define ISIS_PASSWD_TYPE_HMAC_MD5 54
#define ISIS_PASSWD_TYPE_PRIVATE  255
	uint8_t type;
/* Authenticate SNPs? */
#define SNP_AUTH_SEND   0x01
#define SNP_AUTH_RECV   0x02
	uint8_t snp_auth;
	uint8_t passwd[255];
};

/*
 * Supported Protocol IDs
 */
struct nlpids {
	uint8_t count;
	uint8_t nlpids[4]; /* FIXME: enough ? */
};

#endif
