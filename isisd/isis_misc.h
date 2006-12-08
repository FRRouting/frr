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

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _ZEBRA_ISIS_MISC_H
#define _ZEBRA_ISIS_MISC_H

int string2circuit_t (const u_char *);
const char *circuit_t2string (int);
const char *syst2string (int);
struct in_addr newprefix2inaddr (u_char * prefix_start,
				 u_char prefix_masklen);
/*
 * Converting input to memory stored format
 * return value of 0 indicates wrong input
 */
int dotformat2buff (u_char *, const u_char *);
int sysid2buff (u_char *, const u_char *);

/*
 * Printing functions
 */
const char *isonet_print (u_char *, int len);
const char *sysid_print (u_char *);
const char *snpa_print (u_char *);
const char *rawlspid_print (u_char *);
const char *time2string (u_int32_t);
/* typedef struct nlpids nlpids; */
char *nlpid2string (struct nlpids *);

/*
 * misc functions
 */
int speaks (struct nlpids *nlpids, int family);
unsigned long isis_jitter (unsigned long timer, unsigned long jitter);
const char *unix_hostname (void);

/*
 * macros
 */
#define GETSYSID(A,L) (A->area_addr + (A->addr_len - (L + 1)))

/* used for calculating nice string representation instead of plain seconds */

#define SECS_PER_MINUTE 60
#define SECS_PER_HOUR   3600
#define SECS_PER_DAY    86400
#define SECS_PER_WEEK   604800
#define SECS_PER_MONTH  2628000
#define SECS_PER_YEAR   31536000

enum
{
  ISIS_UI_LEVEL_BRIEF,
  ISIS_UI_LEVEL_DETAIL,
  ISIS_UI_LEVEL_EXTENSIVE,
};

#endif
