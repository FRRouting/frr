/*
 * IS-IS Rout(e)ing protocol - isis_misc.h
 *                             Miscellanous routines
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

#ifndef _ZEBRA_ISIS_MISC_H
#define _ZEBRA_ISIS_MISC_H

int string2circuit_t(const char *);
const char *circuit_t2string(int);
const char *circuit_state2string(int state);
const char *circuit_type2string(int type);
const char *syst2string(int);
struct in_addr newprefix2inaddr(uint8_t *prefix_start, uint8_t prefix_masklen);
/*
 * Converting input to memory stored format
 * return value of 0 indicates wrong input
 */
int dotformat2buff(uint8_t *, const char *);
int sysid2buff(uint8_t *, const char *);

/*
 * Printing functions
 */
const char *isonet_print(const uint8_t *, int len);
const char *sysid_print(const uint8_t *);
const char *snpa_print(const uint8_t *);
const char *rawlspid_print(const uint8_t *);
const char *isis_format_id(const uint8_t *id, size_t len);
const char *time2string(uint32_t);
const char *nlpid2str(uint8_t nlpid);
/* typedef struct nlpids nlpids; */
char *nlpid2string(struct nlpids *);
const char *print_sys_hostname(const uint8_t *sysid);
void zlog_dump_data(void *data, int len);

/*
 * misc functions
 */
unsigned long isis_jitter(unsigned long timer, unsigned long jitter);

/*
 * macros
 */
#define GETSYSID(A)                                                            \
	(A->area_addr + (A->addr_len - (ISIS_SYS_ID_LEN + ISIS_NSEL_LEN)))

/* used for calculating nice string representation instead of plain seconds */

#define SECS_PER_MINUTE 60
#define SECS_PER_HOUR   3600
#define SECS_PER_DAY    86400
#define SECS_PER_WEEK   604800
#define SECS_PER_MONTH  2628000
#define SECS_PER_YEAR   31536000

enum { ISIS_UI_LEVEL_BRIEF,
       ISIS_UI_LEVEL_DETAIL,
       ISIS_UI_LEVEL_EXTENSIVE,
};

#include "lib/log.h"
void log_multiline(int priority, const char *prefix, const char *format, ...)
	PRINTF_ATTRIBUTE(3, 4);
struct vty;
void vty_multiline(struct vty *vty, const char *prefix, const char *format, ...)
	PRINTF_ATTRIBUTE(3, 4);
void vty_out_timestr(struct vty *vty, time_t uptime);
#endif
