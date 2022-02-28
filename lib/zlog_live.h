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
	uint64_t ts_sec;
	uint32_t ts_nsec;
	uint32_t prio;
	uint32_t flags;
	uint32_t textlen;

	uint32_t arghdrlen;
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

static inline bool zlog_live_is_null(struct zlog_live_cfg *cfg)
{
	return cfg->target == NULL;
}

extern void zlog_live_close(struct zlog_live_cfg *cfg);
extern void zlog_live_disown(struct zlog_live_cfg *cfg);

#endif /* _FRR_ZLOG_5424_H */
