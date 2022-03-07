/*
 * Copyright (c) 2019-22  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FRR_ZLOG_LIVE_H
#define _FRR_ZLOG_LIVE_H

#include "printfrr.h"

struct zlog_live_hdr {
	/* timestamp (CLOCK_REALTIME) */
	uint64_t ts_sec;
	uint32_t ts_nsec;

	/* length of zlog_live_hdr, including variable length bits and
	 * possible future extensions - aka start of text
	 */
	uint32_t hdrlen;

	/* process & thread ID, meaning depends on OS */
	int64_t pid;
	int64_t tid;

	/* number of lost messages due to best-effort non-blocking mode */
	uint32_t lost_msgs;
	/* syslog priority value */
	uint32_t prio;
	/* flags: currently unused */
	uint32_t flags;
	/* length of message text - extra data (e.g. future key/value metadata)
	 * may follow after it
	 */
	uint32_t textlen;
	/* length of "[XXXXX-XXXXX][EC 0] " header; consumer may want to skip
	 * over it if using the raw values below.  Note that this text may be
	 * absent depending on "log error-category" and "log unique-id"
	 * settings
	 */
	uint32_t texthdrlen;

	/* xref unique identifier, "XXXXX-XXXXX\0" = 12 bytes */
	char uid[12];
	/* EC value */
	uint32_t ec;

	/* recorded printf formatting argument positions (variable length) */
	uint32_t n_argpos;
	struct fmt_outpos argpos[0];
};

struct zlt_live;

struct zlog_live_cfg {
	struct zlt_live *target;

	/* nothing else here */
};

extern void zlog_live_open(struct zlog_live_cfg *cfg, int prio_min,
			   int *other_fd);
extern void zlog_live_open_fd(struct zlog_live_cfg *cfg, int prio_min, int fd);

static inline bool zlog_live_is_null(struct zlog_live_cfg *cfg)
{
	return cfg->target == NULL;
}

extern void zlog_live_close(struct zlog_live_cfg *cfg);
extern void zlog_live_disown(struct zlog_live_cfg *cfg);

#endif /* _FRR_ZLOG_5424_H */
