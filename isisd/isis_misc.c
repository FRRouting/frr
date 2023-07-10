// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_misc.h
 *                             Miscellanous routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#include <zebra.h>

#include "printfrr.h"
#include "stream.h"
#include "vty.h"
#include "hash.h"
#include "if.h"
#include "command.h"
#include "network.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"
#include "isisd/isisd.h"
#include "isisd/isis_misc.h"

#include "isisd/isis_lsp.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_dynhn.h"

/* staticly assigned vars for printing purposes */
static char sys_hostname[ISO_SYSID_STRLEN];
struct in_addr new_prefix;
/* len of xxYxxMxWxdxxhxxmxxs + place for #0 termination */
char datestring[20];
char nlpidstring[30];

/*
 * Returns 0 on error, length of buff on ok
 * extract dot from the dotted str, and insert all the number in a buff
 */
int dotformat2buff(uint8_t *buff, const char *dotted)
{
	int dotlen, len = 0;
	const char *pos = dotted;
	uint8_t number[3];
	int nextdotpos = 2;

	number[2] = '\0';
	dotlen = strlen(dotted);
	if (dotlen > 50) {
		/* this can't be an iso net, its too long */
		return 0;
	}

	while ((pos - dotted) < dotlen && len < 20) {
		if (*pos == '.') {
			/* we expect the . at 2, and than every 5 */
			if ((pos - dotted) != nextdotpos) {
				len = 0;
				break;
			}
			nextdotpos += 5;
			pos++;
			continue;
		}
		/* we must have at least two chars left here */
		if (dotlen - (pos - dotted) < 2) {
			len = 0;
			break;
		}

		if ((isxdigit((unsigned char)*pos)) &&
		    (isxdigit((unsigned char)*(pos + 1)))) {
			memcpy(number, pos, 2);
			pos += 2;
		} else {
			len = 0;
			break;
		}

		*(buff + len) = (char)strtol((char *)number, NULL, 16);
		len++;
	}

	return len;
}

/*
 * conversion of XXXX.XXXX.XXXX to memory
 */
int sysid2buff(uint8_t *buff, const char *dotted)
{
	int len = 0;
	const char *pos = dotted;
	uint8_t number[3];

	number[2] = '\0';
	// surely not a sysid_string if not 14 length
	if (strlen(dotted) != 14) {
		return 0;
	}

	while (len < ISIS_SYS_ID_LEN) {
		if (*pos == '.') {
			/* the . is not positioned correctly */
			if (((pos - dotted) != 4) && ((pos - dotted) != 9)) {
				len = 0;
				break;
			}
			pos++;
			continue;
		}
		if ((isxdigit((unsigned char)*pos)) &&
		    (isxdigit((unsigned char)*(pos + 1)))) {
			memcpy(number, pos, 2);
			pos += 2;
		} else {
			len = 0;
			break;
		}

		*(buff + len) = (char)strtol((char *)number, NULL, 16);
		len++;
	}

	return len;
}

const char *nlpid2str(uint8_t nlpid)
{
	static char buf[4];
	switch (nlpid) {
	case NLPID_IP:
		return "IPv4";
	case NLPID_IPV6:
		return "IPv6";
	case NLPID_SNAP:
		return "SNAP";
	case NLPID_CLNP:
		return "CLNP";
	case NLPID_ESIS:
		return "ES-IS";
	default:
		snprintf(buf, sizeof(buf), "%hhu", nlpid);
		return buf;
	}
}

/*
 * converts the nlpids struct (filled by TLV #129)
 * into a string
 */

char *nlpid2string(struct nlpids *nlpids)
{
	int i;
	char tbuf[256];
	nlpidstring[0] = '\0';

	for (i = 0; i < nlpids->count; i++) {
		snprintf(tbuf, sizeof(tbuf), "%s",
			 nlpid2str(nlpids->nlpids[i]));
		strlcat(nlpidstring, tbuf, sizeof(nlpidstring));
		if (nlpids->count - i > 1)
			strlcat(nlpidstring, ", ", sizeof(nlpidstring));
	}

	return nlpidstring;
}

/*
 * Returns 0 on error, IS-IS Circuit Type on ok
 */
int string2circuit_t(const char *str)
{

	if (!str)
		return 0;

	if (!strcmp(str, "level-1"))
		return IS_LEVEL_1;

	if (!strcmp(str, "level-2-only") || !strcmp(str, "level-2"))
		return IS_LEVEL_2;

	if (!strcmp(str, "level-1-2"))
		return IS_LEVEL_1_AND_2;

	return 0;
}

const char *circuit_state2string(int state)
{

	switch (state) {
	case C_STATE_INIT:
		return "Init";
	case C_STATE_CONF:
		return "Config";
	case C_STATE_UP:
		return "Up";
	default:
		return "Unknown";
	}
	return NULL;
}

const char *circuit_type2string(int type)
{

	switch (type) {
	case CIRCUIT_T_P2P:
		return "p2p";
	case CIRCUIT_T_BROADCAST:
		return "lan";
	case CIRCUIT_T_LOOPBACK:
		return "loopback";
	default:
		return "Unknown";
	}
	return NULL;
}

const char *circuit_t2string(int circuit_t)
{
	switch (circuit_t) {
	case IS_LEVEL_1:
		return "L1";
	case IS_LEVEL_2:
		return "L2";
	case IS_LEVEL_1_AND_2:
		return "L1L2";
	default:
		return "??";
	}

	return NULL; /* not reached */
}

const char *syst2string(int type)
{
	switch (type) {
	case ISIS_SYSTYPE_ES:
		return "ES";
	case ISIS_SYSTYPE_IS:
		return "IS";
	case ISIS_SYSTYPE_L1_IS:
		return "1";
	case ISIS_SYSTYPE_L2_IS:
		return "2";
	default:
		return "??";
	}

	return NULL; /* not reached */
}

const char *isis_hello_padding2string(int hello_padding_type)
{
	switch (hello_padding_type) {
	case ISIS_HELLO_PADDING_DISABLED:
		return "no";
	case ISIS_HELLO_PADDING_DURING_ADJACENCY_FORMATION:
		return "during-adjacency-formation";
	case ISIS_HELLO_PADDING_ALWAYS:
		return "yes";
	}
	return NULL; /* not reached */
}

const char *time2string(uint32_t time)
{
	uint32_t rest;
	char tbuf[32];
	datestring[0] = '\0';

	if (time == 0)
		return "-";

	if (time / SECS_PER_YEAR) {
		snprintf(tbuf, sizeof(tbuf), "%uY", time / SECS_PER_YEAR);
		strlcat(datestring, tbuf, sizeof(datestring));
	}
	rest = time % SECS_PER_YEAR;
	if (rest / SECS_PER_MONTH) {
		snprintf(tbuf, sizeof(tbuf), "%uM", rest / SECS_PER_MONTH);
		strlcat(datestring, tbuf, sizeof(datestring));
	}
	rest = rest % SECS_PER_MONTH;
	if (rest / SECS_PER_WEEK) {
		snprintf(tbuf, sizeof(tbuf), "%uw", rest / SECS_PER_WEEK);
		strlcat(datestring, tbuf, sizeof(datestring));
	}
	rest = rest % SECS_PER_WEEK;
	if (rest / SECS_PER_DAY) {
		snprintf(tbuf, sizeof(tbuf), "%ud", rest / SECS_PER_DAY);
		strlcat(datestring, tbuf, sizeof(datestring));
	}
	rest = rest % SECS_PER_DAY;
	if (rest / SECS_PER_HOUR) {
		snprintf(tbuf, sizeof(tbuf), "%uh", rest / SECS_PER_HOUR);
		strlcat(datestring, tbuf, sizeof(datestring));
	}
	rest = rest % SECS_PER_HOUR;
	if (rest / SECS_PER_MINUTE) {
		snprintf(tbuf, sizeof(tbuf), "%um", rest / SECS_PER_MINUTE);
		strlcat(datestring, tbuf, sizeof(datestring));
	}
	rest = rest % SECS_PER_MINUTE;
	if (rest) {
		snprintf(tbuf, sizeof(tbuf), "%us", rest);
		strlcat(datestring, tbuf, sizeof(datestring));
	}

	return datestring;
}

/*
 * routine to decrement a timer by a random
 * number
 *
 * first argument is the timer and the second is
 * the jitter
 */
unsigned long isis_jitter(unsigned long timer, unsigned long jitter)
{
	int j, k;

	if (jitter >= 100)
		return timer;

	if (timer == 1)
		return timer;
	/*
	 * randomizing just the percent value provides
	 * no good random numbers - hence the spread
	 * to RANDOM_SPREAD (100000), which is ok as
	 * most IS-IS timers are no longer than 16 bit
	 */

	j = 1 + (int)((RANDOM_SPREAD * frr_weak_random()) / (RAND_MAX + 1.0));

	k = timer - (timer * (100 - jitter)) / 100;

	timer = timer - (k * j / RANDOM_SPREAD);

	return timer;
}

struct in_addr newprefix2inaddr(uint8_t *prefix_start, uint8_t prefix_masklen)
{
	memset(&new_prefix, 0, sizeof(new_prefix));
	memcpy(&new_prefix, prefix_start,
	       (prefix_masklen & 0x3F)
		       ? ((((prefix_masklen & 0x3F) - 1) >> 3) + 1)
		       : 0);
	return new_prefix;
}

/*
 * Returns the dynamic hostname associated with the passed system ID.
 * If no dynamic hostname found then returns formatted system ID.
 */
const char *print_sys_hostname(const uint8_t *sysid)
{
	struct isis_dynhn *dyn;
	struct isis *isis = NULL;
	struct listnode *node;

	if (!sysid)
		return "nullsysid";

	/* For our system ID return our host name */
	isis = isis_lookup_by_sysid(sysid);
	if (isis && !CHECK_FLAG(im->options, F_ISIS_UNIT_TEST))
		return cmd_hostname_get();

	for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
		dyn = dynhn_find_by_id(isis, sysid);
		if (dyn)
			return dyn->hostname;
	}

	snprintfrr(sys_hostname, ISO_SYSID_STRLEN, "%pSY", sysid);
	return sys_hostname;
}

/*
 * This function is a generic utility that logs data of given length.
 * Move this to a shared lib so that any protocol can use it.
 */
void zlog_dump_data(void *data, int len)
{
	int i;
	unsigned char *p;
	unsigned char c;
	char bytestr[4];
	char addrstr[10];
	char hexstr[16 * 3 + 5];
	char charstr[16 * 1 + 5];

	p = data;
	memset(bytestr, 0, sizeof(bytestr));
	memset(addrstr, 0, sizeof(addrstr));
	memset(hexstr, 0, sizeof(hexstr));
	memset(charstr, 0, sizeof(charstr));

	for (i = 1; i <= len; i++) {
		c = *p;
		if (isalnum(c) == 0)
			c = '.';

		/* store address for this line */
		if ((i % 16) == 1)
			snprintf(addrstr, sizeof(addrstr), "%p", p);

		/* store hex str (for left side) */
		snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
		strlcat(hexstr, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);

		/* store char str (for right side) */
		snprintf(bytestr, sizeof(bytestr), "%c", c);
		strlcat(charstr, bytestr,
			sizeof(charstr) - strlen(charstr) - 1);

		if ((i % 16) == 0) {
			/* line completed */
			zlog_debug("[%8.8s]   %-50.50s  %s", addrstr, hexstr,
				   charstr);
			hexstr[0] = 0;
			charstr[0] = 0;
		} else if ((i % 8) == 0) {
			/* half line: add whitespaces */
			strlcat(hexstr, "  ",
				sizeof(hexstr) - strlen(hexstr) - 1);
			strlcat(charstr, " ",
				sizeof(charstr) - strlen(charstr) - 1);
		}
		p++; /* next byte */
	}

	/* print rest of buffer if not empty */
	if (strlen(hexstr) > 0)
		zlog_debug("[%8.8s]   %-50.50s  %s", addrstr, hexstr, charstr);
	return;
}

void log_multiline(int priority, const char *prefix, const char *format, ...)
{
	char shortbuf[256];
	va_list ap;
	char *p;

	va_start(ap, format);
	p = vasnprintfrr(MTYPE_TMP, shortbuf, sizeof(shortbuf), format, ap);
	va_end(ap);

	if (!p)
		return;

	char *saveptr = NULL;
	for (char *line = strtok_r(p, "\n", &saveptr); line;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		zlog(priority, "%s%s", prefix, line);
	}

	if (p != shortbuf)
		XFREE(MTYPE_TMP, p);
}

char *log_uptime(time_t uptime, char *buf, size_t nbuf)
{
	struct tm tm;
	time_t difftime = time(NULL);
	difftime -= uptime;
	gmtime_r(&difftime, &tm);

	if (difftime < ONE_DAY_SECOND)
		snprintf(buf, nbuf, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min,
			 tm.tm_sec);
	else if (difftime < ONE_WEEK_SECOND)
		snprintf(buf, nbuf, "%dd%02dh%02dm", tm.tm_yday, tm.tm_hour,
			 tm.tm_min);
	else
		snprintf(buf, nbuf, "%02dw%dd%02dh", tm.tm_yday / 7,
			 tm.tm_yday - ((tm.tm_yday / 7) * 7), tm.tm_hour);

	return buf;
}

void vty_multiline(struct vty *vty, const char *prefix, const char *format, ...)
{
	char shortbuf[256];
	va_list ap;
	char *p;

	va_start(ap, format);
	p = vasnprintfrr(MTYPE_TMP, shortbuf, sizeof(shortbuf), format, ap);
	va_end(ap);

	if (!p)
		return;

	char *saveptr = NULL;
	for (char *line = strtok_r(p, "\n", &saveptr); line;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		vty_out(vty, "%s%s\n", prefix, line);
	}

	if (p != shortbuf)
		XFREE(MTYPE_TMP, p);
}

void vty_out_timestr(struct vty *vty, time_t uptime)
{
	time_t difftime = time(NULL);
	char buf[MONOTIME_STRLEN];

	difftime -= uptime;

	frrtime_to_interval(difftime, buf, sizeof(buf));

	vty_out(vty, "%s ago", buf);
}
