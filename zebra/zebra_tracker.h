/*
 * Zebra Tracker library
 *
 * Copyright 2022 6WIND S.A.
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

#include "tracker.h"

#ifndef __ZEBRA_TRACKER_H__
#define __ZEBRA_TRACKER_H__

#ifdef __cplusplus
extern "C" {
#endif

#define TRACKER_FILEPATTERN_SIZE 32

/** Zebra tracker status definitions. */
enum zebra_tracker_status {
	/* init: status has not been checked or the configuration is invalid */
	ZEBRA_TRACKER_STATUS_INIT = 0,
	ZEBRA_TRACKER_STATUS_DOWN,
	ZEBRA_TRACKER_STATUS_UP,
	ZEBRA_TRACKER_STATUS_DEL,
};

struct zebra_tracker_file {
	char name[TRACKER_NAME_SIZE + 1];
	enum zebra_tracker_status status;

	/* File tracker configuration */
	char path[PATH_MAX + 1];
	bool condition_file_exists;
	char pattern[TRACKER_FILEPATTERN_SIZE + 1];
	bool exact_pattern;

	/* inotify file tracking */
	struct event *event;
};

void zebra_tracker_zsend_all(int proto);
struct zebra_tracker_file *zebra_tracker_file_get(const char *name);
struct zebra_tracker_file *zebra_tracker_file_new(const char *name);
void zebra_tracker_file_free(const char *name);
struct zebra_tracker_file *zebra_tracker_filepath_set(const char *name,
						      const char *filepath);
void zebra_tracker_filepath_unset(const char *name);
struct zebra_tracker_file *
zebra_tracker_filepattern_set(const char *name, const char *filepattern);
void zebra_tracker_filepattern_unset(const char *name);
void zebra_tracker_filepattern_exact_set(const char *name, bool exact);
void zebra_tracker_fileexists_set(const char *name, bool condition_file_exists);

void zebra_tracker_file_set_status(struct zebra_tracker_file *tracker_file,
				   enum zebra_tracker_status status);

void zebra_tracker_file_update(const char *name);


void zebra_tracker_notify_file_init(struct zebra_tracker_file *tracker_file);
void zebra_tracker_notify_file_close(struct zebra_tracker_file *tracker_file);

void cli_show_tracker(struct vty *vty, const struct lyd_node *dnode,
		      bool show_defaults __attribute__((__unused__)));
extern void zebra_tracker_init(void);


#ifdef __cplusplus
}
#endif

#endif /*__ZEBRA_TRACKER_H__ */
