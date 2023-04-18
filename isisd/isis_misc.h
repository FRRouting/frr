// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_misc.h
 *                             Miscellanous routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#ifndef _ZEBRA_ISIS_MISC_H
#define _ZEBRA_ISIS_MISC_H

int string2circuit_t(const char *);
const char *circuit_t2string(int);
const char *circuit_state2string(int state);
const char *circuit_type2string(int type);
const char *syst2string(int);
const char *isis_hello_padding2string(int hello_padding_type);
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
	PRINTFRR(3, 4);
char *log_uptime(time_t uptime, char *buf, size_t nbuf);
struct vty;
void vty_multiline(struct vty *vty, const char *prefix, const char *format, ...)
	PRINTFRR(3, 4);
void vty_out_timestr(struct vty *vty, time_t uptime);
#endif
