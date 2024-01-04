// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP-4 dump routine
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>
#include <sys/stat.h>

#include "log.h"
#include "stream.h"
#include "sockunion.h"
#include "command.h"
#include "prefix.h"
#include "frrevent.h"
#include "linklist.h"
#include "queue.h"
#include "memory.h"
#include "filter.h"

#include "bgpd/bgp_table.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_packet.h"

enum bgp_dump_type {
	BGP_DUMP_ALL,
	BGP_DUMP_ALL_ET,
	BGP_DUMP_UPDATES,
	BGP_DUMP_UPDATES_ET,
	BGP_DUMP_ROUTES
};

static const struct bgp_dump_type_map {
	enum bgp_dump_type type;
	const char *str;
} bgp_dump_type_map[] = {
	{BGP_DUMP_ALL, "all"},		 {BGP_DUMP_ALL_ET, "all-et"},
	{BGP_DUMP_UPDATES, "updates"},   {BGP_DUMP_UPDATES_ET, "updates-et"},
	{BGP_DUMP_ROUTES, "routes-mrt"}, {0, NULL},
};

enum MRT_MSG_TYPES {
	MSG_NULL,
	MSG_START,		  /* sender is starting up */
	MSG_DIE,		  /* receiver should shut down */
	MSG_I_AM_DEAD,		  /* sender is shutting down */
	MSG_PEER_DOWN,		  /* sender's peer is down */
	MSG_PROTOCOL_BGP,	 /* msg is a BGP packet */
	MSG_PROTOCOL_RIP,	 /* msg is a RIP packet */
	MSG_PROTOCOL_IDRP,	/* msg is an IDRP packet */
	MSG_PROTOCOL_RIPNG,       /* msg is a RIPNG packet */
	MSG_PROTOCOL_BGP4PLUS,    /* msg is a BGP4+ packet */
	MSG_PROTOCOL_BGP4PLUS_01, /* msg is a BGP4+ (draft 01) packet */
	MSG_PROTOCOL_OSPF,	/* msg is an OSPF packet */
	MSG_TABLE_DUMP,		  /* routing table dump */
	MSG_TABLE_DUMP_V2	 /* routing table dump, version 2 */
};

struct bgp_dump {
	enum bgp_dump_type type;

	char *filename;

	FILE *fp;

	unsigned int interval;

	char *interval_str;

	struct event *t_interval;
};

static int bgp_dump_unset(struct bgp_dump *bgp_dump);
static void bgp_dump_interval_func(struct event *);

/* BGP packet dump output buffer. */
struct stream *bgp_dump_obuf;

/* BGP dump strucuture for 'dump bgp all' */
struct bgp_dump bgp_dump_all;

/* BGP dump structure for 'dump bgp updates' */
struct bgp_dump bgp_dump_updates;

/* BGP dump structure for 'dump bgp routes' */
struct bgp_dump bgp_dump_routes;

static FILE *bgp_dump_open_file(struct bgp_dump *bgp_dump)
{
	int ret;
	time_t clock;
	struct tm tm;
	char fullpath[MAXPATHLEN];
	char realpath[MAXPATHLEN];
	mode_t oldumask;

	time(&clock);
	localtime_r(&clock, &tm);

	if (bgp_dump->filename[0] != DIRECTORY_SEP) {
		snprintf(fullpath, sizeof(fullpath), "%s/%s", vty_get_cwd(),
			 bgp_dump->filename);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
		/* user supplied date/time format string */
		ret = strftime(realpath, MAXPATHLEN, fullpath, &tm);
	} else
		ret = strftime(realpath, MAXPATHLEN, bgp_dump->filename, &tm);
#pragma GCC diagnostic pop

	if (ret == 0) {
		flog_warn(EC_BGP_DUMP, "%s: strftime error", __func__);
		return NULL;
	}

	if (bgp_dump->fp)
		fclose(bgp_dump->fp);


	oldumask = umask(0777 & ~LOGFILE_MASK);
	bgp_dump->fp = fopen(realpath, "w");

	if (bgp_dump->fp == NULL) {
		flog_warn(EC_BGP_DUMP, "%s: %s: %s", __func__, realpath,
			  strerror(errno));
		umask(oldumask);
		return NULL;
	}
	umask(oldumask);

	return bgp_dump->fp;
}

static int bgp_dump_interval_add(struct bgp_dump *bgp_dump, int interval)
{
	int secs_into_day;
	time_t t;
	struct tm tm;

	if (interval > 0) {
		/* Periodic dump every interval seconds */
		if ((interval < 86400) && ((86400 % interval) == 0)) {
			/* Dump at predictable times: if a day has a whole
			 * number of
			 * intervals, dump every interval seconds starting from
			 * midnight
			 */
			(void)time(&t);
			localtime_r(&t, &tm);
			secs_into_day = tm.tm_sec + 60 * tm.tm_min
					+ 60 * 60 * tm.tm_hour;
			interval = interval
				   - secs_into_day % interval; /* always > 0 */
		}
		event_add_timer(bm->master, bgp_dump_interval_func, bgp_dump,
				interval, &bgp_dump->t_interval);
	} else {
		/* One-off dump: execute immediately, don't affect any scheduled
		 * dumps */
		event_add_event(bm->master, bgp_dump_interval_func, bgp_dump, 0,
				&bgp_dump->t_interval);
	}

	return 0;
}

/* Dump common header. */
static void bgp_dump_header(struct stream *obuf, int type, int subtype,
			    int dump_type)
{
	struct timeval clock;
	long msecs;
	time_t secs;

	if ((dump_type == BGP_DUMP_ALL_ET || dump_type == BGP_DUMP_UPDATES_ET)
	    && type == MSG_PROTOCOL_BGP4MP)
		type = MSG_PROTOCOL_BGP4MP_ET;

	gettimeofday(&clock, NULL);

	secs = clock.tv_sec;
	msecs = clock.tv_usec;

	/* Put dump packet header. */
	stream_putl(obuf, secs);
	stream_putw(obuf, type);
	stream_putw(obuf, subtype);
	stream_putl(obuf, 0); /* len */

	/* Adding microseconds for the MRT Extended Header */
	if (type == MSG_PROTOCOL_BGP4MP_ET)
		stream_putl(obuf, msecs);
}

static void bgp_dump_set_size(struct stream *s, int type)
{
	/*
	 * The BGP_DUMP_HEADER_SIZE stay at 12 event when ET:
	 * "The Microsecond Timestamp is included in the computation
	 *  of the Length field value." (RFC6396 2011)
	 */
	stream_putl_at(s, 8, stream_get_endp(s) - BGP_DUMP_HEADER_SIZE);
}

static void bgp_dump_routes_index_table(struct bgp *bgp)
{
	struct peer *peer;
	struct listnode *node;
	uint16_t peerno = 1;
	struct stream *obuf;

	obuf = bgp_dump_obuf;
	stream_reset(obuf);

	/* MRT header */
	bgp_dump_header(obuf, MSG_TABLE_DUMP_V2, TABLE_DUMP_V2_PEER_INDEX_TABLE,
			BGP_DUMP_ROUTES);

	/* Collector BGP ID */
	stream_put_in_addr(obuf, &bgp->router_id);

	/* View name */
	if (bgp->name_pretty) {
		stream_putw(obuf, strlen(bgp->name_pretty));
		stream_put(obuf, bgp->name_pretty, strlen(bgp->name_pretty));
	} else {
		stream_putw(obuf, 0);
	}

	/* Peer count ( plus one extra internal peer ) */
	stream_putw(obuf, listcount(bgp->peer) + 1);

	/* Populate fake peer at index 0, for locally originated routes */
	/* Peer type (IPv4) */
	stream_putc(obuf,
		    TABLE_DUMP_V2_PEER_INDEX_TABLE_AS4
			    + TABLE_DUMP_V2_PEER_INDEX_TABLE_IP);
	/* Peer BGP ID (0.0.0.0) */
	stream_putl(obuf, 0);
	/* Peer IP address (0.0.0.0) */
	stream_putl(obuf, 0);
	/* Peer ASN (0) */
	stream_putl(obuf, 0);

	/* Walk down all peers */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		int family = sockunion_family(&peer->connection->su);

		/* Peer's type */
		if (family == AF_INET) {
			stream_putc(
				obuf,
				TABLE_DUMP_V2_PEER_INDEX_TABLE_AS4
					+ TABLE_DUMP_V2_PEER_INDEX_TABLE_IP);
		} else if (family == AF_INET6) {
			stream_putc(
				obuf,
				TABLE_DUMP_V2_PEER_INDEX_TABLE_AS4
					+ TABLE_DUMP_V2_PEER_INDEX_TABLE_IP6);
		}

		/* Peer's BGP ID */
		stream_put_in_addr(obuf, &peer->remote_id);

		/* Peer's IP address */
		if (family == AF_INET) {
			stream_put_in_addr(obuf,
					   &peer->connection->su.sin.sin_addr);
		} else if (family == AF_INET6) {
			stream_write(obuf,
				     (uint8_t *)&peer->connection->su.sin6
					     .sin6_addr,
				     IPV6_MAX_BYTELEN);
		}

		/* Peer's AS number. */
		/* Note that, as this is an AS4 compliant quagga, the RIB is
		 * always AS4 */
		stream_putl(obuf, peer->as);

		/* Store the peer number for this peer */
		peer->table_dump_index = peerno;
		peerno++;
	}

	bgp_dump_set_size(obuf, MSG_TABLE_DUMP_V2);

	fwrite(STREAM_DATA(obuf), stream_get_endp(obuf), 1, bgp_dump_routes.fp);
	fflush(bgp_dump_routes.fp);
}

static struct bgp_path_info *
bgp_dump_route_node_record(int afi, struct bgp_dest *dest,
			   struct bgp_path_info *path, unsigned int seq)
{
	struct stream *obuf;
	size_t sizep;
	size_t endp;
	bool addpath_capable;
	const struct prefix *p = bgp_dest_get_prefix(dest);

	obuf = bgp_dump_obuf;
	stream_reset(obuf);

	addpath_capable = bgp_addpath_encode_rx(path->peer, afi, SAFI_UNICAST);

	/* MRT header */
	if (afi == AFI_IP && addpath_capable)
		bgp_dump_header(obuf, MSG_TABLE_DUMP_V2,
				TABLE_DUMP_V2_RIB_IPV4_UNICAST_ADDPATH,
				BGP_DUMP_ROUTES);
	else if (afi == AFI_IP)
		bgp_dump_header(obuf, MSG_TABLE_DUMP_V2,
				TABLE_DUMP_V2_RIB_IPV4_UNICAST,
				BGP_DUMP_ROUTES);
	else if (afi == AFI_IP6 && addpath_capable)
		bgp_dump_header(obuf, MSG_TABLE_DUMP_V2,
				TABLE_DUMP_V2_RIB_IPV6_UNICAST_ADDPATH,
				BGP_DUMP_ROUTES);
	else if (afi == AFI_IP6)
		bgp_dump_header(obuf, MSG_TABLE_DUMP_V2,
				TABLE_DUMP_V2_RIB_IPV6_UNICAST,
				BGP_DUMP_ROUTES);

	/* Sequence number */
	stream_putl(obuf, seq);

	/* Prefix length */
	stream_putc(obuf, p->prefixlen);

	/* Prefix */
	if (afi == AFI_IP) {
		/* We'll dump only the useful bits (those not 0), but have to
		 * align on 8 bits */
		stream_write(obuf, (uint8_t *)&p->u.prefix4,
			     (p->prefixlen + 7) / 8);
	} else if (afi == AFI_IP6) {
		/* We'll dump only the useful bits (those not 0), but have to
		 * align on 8 bits */
		stream_write(obuf, (uint8_t *)&p->u.prefix6,
			     (p->prefixlen + 7) / 8);
	}

	/* Save where we are now, so we can overwride the entry count later */
	sizep = stream_get_endp(obuf);

	/* Entry count */
	uint16_t entry_count = 0;

	/* Entry count, note that this is overwritten later */
	stream_putw(obuf, 0);

	endp = stream_get_endp(obuf);
	for (; path; path = path->next) {
		size_t cur_endp;

		/* Peer index */
		stream_putw(obuf, path->peer->table_dump_index);

		/* Originated */
		stream_putl(obuf, time(NULL) - (monotime(NULL) - path->uptime));

		/*Path Identifier*/
		if (addpath_capable) {
			stream_putl(obuf, path->addpath_rx_id);
		}

		/* Dump attribute. */
		/* Skip prefix & AFI/SAFI for MP_NLRI */
		bgp_dump_routes_attr(obuf, path, p);

		cur_endp = stream_get_endp(obuf);
		if (cur_endp > BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE
				       + BGP_DUMP_MSG_HEADER
				       + BGP_DUMP_HEADER_SIZE) {
			stream_set_endp(obuf, endp);
			break;
		}

		entry_count++;
		endp = cur_endp;
	}

	/* Overwrite the entry count, now that we know the right number */
	stream_putw_at(obuf, sizep, entry_count);

	bgp_dump_set_size(obuf, MSG_TABLE_DUMP_V2);
	fwrite(STREAM_DATA(obuf), stream_get_endp(obuf), 1, bgp_dump_routes.fp);

	return path;
}


/* Runs under child process. */
static unsigned int bgp_dump_routes_func(int afi, int first_run,
					 unsigned int seq)
{
	struct bgp_path_info *path;
	struct bgp_dest *dest;
	struct bgp *bgp;
	struct bgp_table *table;

	bgp = bgp_get_default();
	if (!bgp)
		return seq;

	if (bgp_dump_routes.fp == NULL)
		return seq;

	/* Note that bgp_dump_routes_index_table will do ipv4 and ipv6 peers,
	   so this should only be done on the first call to
	   bgp_dump_routes_func.
	   ( this function will be called once for ipv4 and once for ipv6 ) */
	if (first_run)
		bgp_dump_routes_index_table(bgp);

	/* Walk down each BGP route. */
	table = bgp->rib[afi][SAFI_UNICAST];

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		path = bgp_dest_get_bgp_path_info(dest);
		while (path) {
			path = bgp_dump_route_node_record(afi, dest, path, seq);
			seq++;
		}
	}

	fflush(bgp_dump_routes.fp);

	return seq;
}

static void bgp_dump_interval_func(struct event *t)
{
	struct bgp_dump *bgp_dump;
	bgp_dump = EVENT_ARG(t);

	/* Reschedule dump even if file couldn't be opened this time... */
	if (bgp_dump_open_file(bgp_dump) != NULL) {
		/* In case of bgp_dump_routes, we need special route dump
		 * function. */
		if (bgp_dump->type == BGP_DUMP_ROUTES) {
			unsigned int seq = bgp_dump_routes_func(AFI_IP, 1, 0);
			bgp_dump_routes_func(AFI_IP6, 0, seq);
			/* Close the file now. For a RIB dump there's no point
			 * in leaving
			 * it open until the next scheduled dump starts. */
			fclose(bgp_dump->fp);
			bgp_dump->fp = NULL;
		}
	}

	/* if interval is set reschedule */
	if (bgp_dump->interval > 0)
		bgp_dump_interval_add(bgp_dump, bgp_dump->interval);
}

/* Dump common information. */
static void bgp_dump_common(struct stream *obuf, struct peer *peer,
			    int forceas4)
{
	char empty[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	/* Source AS number and Destination AS number. */
	if (forceas4 || CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV)) {
		stream_putl(obuf, peer->as);
		stream_putl(obuf, peer->local_as);
	} else {
		stream_putw(obuf, peer->as);
		stream_putw(obuf, peer->local_as);
	}

	if (peer->connection->su.sa.sa_family == AF_INET) {
		stream_putw(obuf, peer->ifp ? peer->ifp->ifindex : 0);
		stream_putw(obuf, AFI_IP);

		stream_put(obuf, &peer->connection->su.sin.sin_addr,
			   IPV4_MAX_BYTELEN);

		if (peer->su_local)
			stream_put(obuf, &peer->su_local->sin.sin_addr,
				   IPV4_MAX_BYTELEN);
		else
			stream_put(obuf, empty, IPV4_MAX_BYTELEN);
	} else if (peer->connection->su.sa.sa_family == AF_INET6) {
		/* Interface Index and Address family. */
		stream_putw(obuf, peer->ifp ? peer->ifp->ifindex : 0);
		stream_putw(obuf, AFI_IP6);

		/* Source IP Address and Destination IP Address. */
		stream_put(obuf, &peer->connection->su.sin6.sin6_addr,
			   IPV6_MAX_BYTELEN);

		if (peer->su_local)
			stream_put(obuf, &peer->su_local->sin6.sin6_addr,
				   IPV6_MAX_BYTELEN);
		else
			stream_put(obuf, empty, IPV6_MAX_BYTELEN);
	}
}

/* Dump BGP status change. */
int bgp_dump_state(struct peer *peer)
{
	struct stream *obuf;

	/* If dump file pointer is disabled return immediately. */
	if (bgp_dump_all.fp == NULL)
		return 0;

	/* Make dump stream. */
	obuf = bgp_dump_obuf;
	stream_reset(obuf);

	bgp_dump_header(obuf, MSG_PROTOCOL_BGP4MP, BGP4MP_STATE_CHANGE_AS4,
			bgp_dump_all.type);
	bgp_dump_common(obuf, peer, 1); /* force this in as4speak*/

	stream_putw(obuf, peer->connection->ostatus);
	stream_putw(obuf, peer->connection->status);

	/* Set length. */
	bgp_dump_set_size(obuf, MSG_PROTOCOL_BGP4MP);

	/* Write to the stream. */
	fwrite(STREAM_DATA(obuf), stream_get_endp(obuf), 1, bgp_dump_all.fp);
	fflush(bgp_dump_all.fp);
	return 0;
}

static void bgp_dump_packet_func(struct bgp_dump *bgp_dump, struct peer *peer,
				 struct stream *packet)
{
	struct stream *obuf;
	bool addpath_capable = false;
	/* If dump file pointer is disabled return immediately. */
	if (bgp_dump->fp == NULL)
		return;
	if (peer->connection->su.sa.sa_family == AF_INET) {
		addpath_capable =
			bgp_addpath_encode_rx(peer, AFI_IP, SAFI_UNICAST);
	} else if (peer->connection->su.sa.sa_family == AF_INET6) {
		addpath_capable =
			bgp_addpath_encode_rx(peer, AFI_IP6, SAFI_UNICAST);
	}

	/* Make dump stream. */
	obuf = bgp_dump_obuf;
	stream_reset(obuf);

	/* Dump header and common part. */
	if (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV) && addpath_capable) {
		bgp_dump_header(obuf, MSG_PROTOCOL_BGP4MP,
				BGP4MP_MESSAGE_AS4_ADDPATH, bgp_dump->type);
	} else if (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV)) {
		bgp_dump_header(obuf, MSG_PROTOCOL_BGP4MP, BGP4MP_MESSAGE_AS4,
				bgp_dump->type);
	} else if (addpath_capable) {
		bgp_dump_header(obuf, MSG_PROTOCOL_BGP4MP,
				BGP4MP_MESSAGE_ADDPATH, bgp_dump->type);
	} else {
		bgp_dump_header(obuf, MSG_PROTOCOL_BGP4MP, BGP4MP_MESSAGE,
				bgp_dump->type);
	}
	bgp_dump_common(obuf, peer, 0);

	/* Packet contents. */
	stream_put(obuf, STREAM_DATA(packet), stream_get_endp(packet));

	/* Set length. */
	bgp_dump_set_size(obuf, MSG_PROTOCOL_BGP4MP);

	/* Write to the stream. */
	fwrite(STREAM_DATA(obuf), stream_get_endp(obuf), 1, bgp_dump->fp);
	fflush(bgp_dump->fp);
}

/* Called from bgp_packet.c when BGP packet is received. */
static int bgp_dump_packet(struct peer *peer, uint8_t type, bgp_size_t size,
		struct stream *packet)
{
	/* bgp_dump_all. */
	bgp_dump_packet_func(&bgp_dump_all, peer, packet);

	/* bgp_dump_updates. */
	if (type == BGP_MSG_UPDATE)
		bgp_dump_packet_func(&bgp_dump_updates, peer, packet);
	return 0;
}

static unsigned int bgp_dump_parse_time(const char *str)
{
	int i;
	int len;
	int seen_h;
	int seen_m;
	int time;
	unsigned int total;

	time = 0;
	total = 0;
	seen_h = 0;
	seen_m = 0;
	len = strlen(str);

	for (i = 0; i < len; i++) {
		if (isdigit((unsigned char)str[i])) {
			time *= 10;
			time += str[i] - '0';
		} else if (str[i] == 'H' || str[i] == 'h') {
			if (seen_h)
				return 0;
			if (seen_m)
				return 0;
			total += time * 60 * 60;
			time = 0;
			seen_h = 1;
		} else if (str[i] == 'M' || str[i] == 'm') {
			if (seen_m)
				return 0;
			total += time * 60;
			time = 0;
			seen_m = 1;
		} else
			return 0;
	}
	return total + time;
}

static int bgp_dump_set(struct vty *vty, struct bgp_dump *bgp_dump,
			enum bgp_dump_type type, const char *path,
			const char *interval_str)
{
	unsigned int interval;

	/* Don't schedule duplicate dumps if the dump command is given twice */
	if (bgp_dump->filename && strcmp(path, bgp_dump->filename) == 0
	    && type == bgp_dump->type) {
		if (interval_str) {
			if (bgp_dump->interval_str
			    && strcmp(bgp_dump->interval_str, interval_str)
				       == 0)
				return CMD_SUCCESS;
		} else {
			if (!bgp_dump->interval_str)
				return CMD_SUCCESS;
		}
	}

	/* Removing previous config */
	bgp_dump_unset(bgp_dump);

	if (interval_str) {
		/* Check interval string. */
		interval = bgp_dump_parse_time(interval_str);
		if (interval == 0) {
			vty_out(vty, "Malformed interval string\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* Setting interval string */
		bgp_dump->interval_str =
			XSTRDUP(MTYPE_BGP_DUMP_STR, interval_str);
	} else {
		interval = 0;
	}

	/* Set type. */
	bgp_dump->type = type;

	/* Set interval */
	bgp_dump->interval = interval;

	/* Set file name. */
	bgp_dump->filename = XSTRDUP(MTYPE_BGP_DUMP_STR, path);

	/* Create interval thread. */
	bgp_dump_interval_add(bgp_dump, interval);

	/* This should be called when interval is expired. */
	bgp_dump_open_file(bgp_dump);

	return CMD_SUCCESS;
}

static int bgp_dump_unset(struct bgp_dump *bgp_dump)
{
	/* Removing file name. */
	XFREE(MTYPE_BGP_DUMP_STR, bgp_dump->filename);

	/* Closing file. */
	if (bgp_dump->fp) {
		fclose(bgp_dump->fp);
		bgp_dump->fp = NULL;
	}

	/* Removing interval event. */
	EVENT_OFF(bgp_dump->t_interval);

	bgp_dump->interval = 0;

	/* Removing interval string. */
	XFREE(MTYPE_BGP_DUMP_STR, bgp_dump->interval_str);

	return CMD_SUCCESS;
}

DEFUN (dump_bgp_all,
       dump_bgp_all_cmd,
       "dump bgp <all|all-et|updates|updates-et|routes-mrt> PATH [INTERVAL]",
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump all BGP packets\nDump all BGP packets (Extended Timestamp Header)\n"
       "Dump BGP updates only\nDump BGP updates only (Extended Timestamp Header)\n"
       "Dump whole BGP routing table\n"
       "Output filename\n"
       "Interval of output\n")
{
	int idx_dump_routes = 2;
	int idx_path = 3;
	int idx_interval = 4;
	int bgp_dump_type = 0;
	const char *interval = NULL;
	struct bgp_dump *bgp_dump_struct = NULL;
	const struct bgp_dump_type_map *map = NULL;

	for (map = bgp_dump_type_map; map->str; map++)
		if (strmatch(argv[idx_dump_routes]->text, map->str))
			bgp_dump_type = map->type;

	switch (bgp_dump_type) {
	case BGP_DUMP_ALL:
	case BGP_DUMP_ALL_ET:
		bgp_dump_struct = &bgp_dump_all;
		break;
	case BGP_DUMP_UPDATES:
	case BGP_DUMP_UPDATES_ET:
		bgp_dump_struct = &bgp_dump_updates;
		break;
	case BGP_DUMP_ROUTES:
	default:
		bgp_dump_struct = &bgp_dump_routes;
		break;
	}

	/* When an interval is given */
	if (argc == idx_interval + 1)
		interval = argv[idx_interval]->arg;

	return bgp_dump_set(vty, bgp_dump_struct, bgp_dump_type,
			    argv[idx_path]->arg, interval);
}

DEFUN (no_dump_bgp_all,
       no_dump_bgp_all_cmd,
       "no dump bgp <all|all-et|updates|updates-et|routes-mrt> [PATH [INTERVAL]]",
       NO_STR
       "Stop dump packet\n"
       "Stop BGP packet dump\n"
       "Stop dump process all\n"
       "Stop dump process all-et\n"
       "Stop dump process updates\n"
       "Stop dump process updates-et\n"
       "Stop dump process route-mrt\n"
       "Output filename\n"
       "Interval of output\n")
{
	int idx_dump_routes = 3;
	int bgp_dump_type = 0;
	const struct bgp_dump_type_map *map = NULL;
	struct bgp_dump *bgp_dump_struct = NULL;

	for (map = bgp_dump_type_map; map->str; map++)
		if (strmatch(argv[idx_dump_routes]->text, map->str))
			bgp_dump_type = map->type;

	switch (bgp_dump_type) {
	case BGP_DUMP_ALL:
	case BGP_DUMP_ALL_ET:
		bgp_dump_struct = &bgp_dump_all;
		break;
	case BGP_DUMP_UPDATES:
	case BGP_DUMP_UPDATES_ET:
		bgp_dump_struct = &bgp_dump_updates;
		break;
	case BGP_DUMP_ROUTES:
	default:
		bgp_dump_struct = &bgp_dump_routes;
		break;
	}

	return bgp_dump_unset(bgp_dump_struct);
}

static int config_write_bgp_dump(struct vty *vty);
/* BGP node structure. */
static struct cmd_node bgp_dump_node = {
	.name = "dump",
	.node = DUMP_NODE,
	.prompt = "",
	.config_write = config_write_bgp_dump,
};

static int config_write_bgp_dump(struct vty *vty)
{
	if (bgp_dump_all.filename) {
		const char *type_str = "all";
		if (bgp_dump_all.type == BGP_DUMP_ALL_ET)
			type_str = "all-et";

		if (bgp_dump_all.interval_str)
			vty_out(vty, "dump bgp %s %s %s\n", type_str,
				bgp_dump_all.filename,
				bgp_dump_all.interval_str);
		else
			vty_out(vty, "dump bgp %s %s\n", type_str,
				bgp_dump_all.filename);
	}
	if (bgp_dump_updates.filename) {
		const char *type_str = "updates";
		if (bgp_dump_updates.type == BGP_DUMP_UPDATES_ET)
			type_str = "updates-et";

		if (bgp_dump_updates.interval_str)
			vty_out(vty, "dump bgp %s %s %s\n", type_str,
				bgp_dump_updates.filename,
				bgp_dump_updates.interval_str);
		else
			vty_out(vty, "dump bgp %s %s\n", type_str,
				bgp_dump_updates.filename);
	}
	if (bgp_dump_routes.filename) {
		if (bgp_dump_routes.interval_str)
			vty_out(vty, "dump bgp routes-mrt %s %s\n",
				bgp_dump_routes.filename,
				bgp_dump_routes.interval_str);
		else
			vty_out(vty, "dump bgp routes-mrt %s\n",
				bgp_dump_routes.filename);
	}
	return 0;
}

/* Initialize BGP packet dump functionality. */
void bgp_dump_init(void)
{
	memset(&bgp_dump_all, 0, sizeof(bgp_dump_all));
	memset(&bgp_dump_updates, 0, sizeof(bgp_dump_updates));
	memset(&bgp_dump_routes, 0, sizeof(bgp_dump_routes));

	bgp_dump_obuf =
		stream_new(BGP_MAX_PACKET_SIZE + BGP_MAX_PACKET_SIZE_OVERFLOW);

	install_node(&bgp_dump_node);

	install_element(CONFIG_NODE, &dump_bgp_all_cmd);
	install_element(CONFIG_NODE, &no_dump_bgp_all_cmd);

	hook_register(bgp_packet_dump, bgp_dump_packet);
	hook_register(peer_status_changed, bgp_dump_state);
}

void bgp_dump_finish(void)
{
	bgp_dump_unset(&bgp_dump_all);
	bgp_dump_unset(&bgp_dump_updates);
	bgp_dump_unset(&bgp_dump_routes);

	stream_free(bgp_dump_obuf);
	bgp_dump_obuf = NULL;
	hook_unregister(bgp_packet_dump, bgp_dump_packet);
	hook_unregister(peer_status_changed, bgp_dump_state);
}
