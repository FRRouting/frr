// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Logging - Filtered file log target
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Stephen Worley
 */

#include <zebra.h>

#include "frr_pthread.h"
#include "log.h"

static pthread_mutex_t logfilterlock = PTHREAD_MUTEX_INITIALIZER;
static char zlog_filters[ZLOG_FILTERS_MAX][ZLOG_FILTER_LENGTH_MAX + 1];
static uint8_t zlog_filter_count;

/*
 * look for a match on the filter in the current filters,
 * logfilterlock must be held
 */
static int zlog_filter_lookup(const char *lookup)
{
	for (int i = 0; i < zlog_filter_count; i++) {
		if (strncmp(lookup, zlog_filters[i], sizeof(zlog_filters[0]))
		    == 0)
			return i;
	}
	return -1;
}

void zlog_filter_clear(void)
{
	frr_with_mutex (&logfilterlock) {
		zlog_filter_count = 0;
	}
}

int zlog_filter_add(const char *filter)
{
	frr_with_mutex (&logfilterlock) {
		if (zlog_filter_count >= ZLOG_FILTERS_MAX)
			return 1;

		if (zlog_filter_lookup(filter) != -1)
			/* Filter already present */
			return -1;

		strlcpy(zlog_filters[zlog_filter_count], filter,
			sizeof(zlog_filters[0]));

		if (zlog_filters[zlog_filter_count][0] == '\0')
			/* Filter was either empty or didn't get copied
			 * correctly
			 */
			return -1;

		zlog_filter_count++;
	}
	return 0;
}

int zlog_filter_del(const char *filter)
{
	frr_with_mutex (&logfilterlock) {
		int found_idx = zlog_filter_lookup(filter);
		int last_idx = zlog_filter_count - 1;

		if (found_idx == -1)
			/* Didn't find the filter to delete */
			return -1;

		/* Adjust the filter array */
		memmove(zlog_filters[found_idx], zlog_filters[found_idx + 1],
			(last_idx - found_idx) * sizeof(zlog_filters[0]));

		zlog_filter_count--;
	}
	return 0;
}

/* Dump all filters to buffer, delimited by new line */
int zlog_filter_dump(char *buf, size_t max_size)
{
	int len = 0;

	frr_with_mutex (&logfilterlock) {
		for (int i = 0; i < zlog_filter_count; i++) {
			int ret;

			ret = snprintf(buf + len, max_size - len, " %s\n",
				       zlog_filters[i]);
			len += ret;
			if ((ret < 0) || ((size_t)len >= max_size))
				return -1;
		}
	}

	return len;
}

static int search_buf(const char *buf, size_t len)
{
	char *found = NULL;

	frr_with_mutex (&logfilterlock) {
		for (int i = 0; i < zlog_filter_count; i++) {
			found = memmem(buf, len, zlog_filters[i],
				       strlen(zlog_filters[i]));
			if (found != NULL)
				return 0;
		}
	}

	return -1;
}

static void zlog_filterfile_fd(struct zlog_target *zt, struct zlog_msg *msgs[],
			       size_t nmsgs)
{
	struct zlog_msg *msgfilt[nmsgs];
	size_t i, o = 0;
	const char *text;
	size_t text_len;

	for (i = 0; i < nmsgs; i++) {
		if (zlog_msg_prio(msgs[i]) >= LOG_DEBUG) {
			text = zlog_msg_text(msgs[i], &text_len);
			if (search_buf(text, text_len) < 0)
				continue;
		}
		msgfilt[o++] = msgs[i];
	}

	if (o)
		zlog_fd(zt, msgfilt, o);
}

void zlog_filterfile_init(struct zlog_cfg_filterfile *zcf)
{
	zlog_file_init(&zcf->parent);
	zcf->parent.zlog_wrap = zlog_filterfile_fd;
}

void zlog_filterfile_fini(struct zlog_cfg_filterfile *zcf)
{
	zlog_file_fini(&zcf->parent);
}
