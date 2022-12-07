/*
 * Zebra Tracker Notify
 *
 * Copyright 2022 6WIND S.A.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include <sys/inotify.h>

#include "frrevent.h"
#include "debug.h"

#include "zebra_router.h"
#include "zebra_tracker.h"

#define ZEBRA_TRACKER_FILE_RETRY 1

static void
zebra_tracker_notify_file_status(struct zebra_tracker_file *tracker_file)
{
	char buf[BUFSIZ], *cp;
	int line = 0;
	FILE *file;

	if (tracker_file->condition_file_exists) {
		zebra_tracker_file_set_status(tracker_file,
					      ZEBRA_TRACKER_STATUS_UP);
		return;
	}

	file = fopen(tracker_file->path, "r");

	if (!file) {
		zlog_err("%s: cannot open the file %s", __func__,
			 tracker_file->path);
		return;
	}

	while (fgets(buf, BUFSIZ, file)) {
		cp = buf;

		while (*cp != '\r' && *cp != '\n' && *cp != '\0')
			cp++;
		*cp = '\0';

		line++;
	}

	if (line == 0) {
		if (IS_ZEBRA_DEBUG_TRACKER)
			zlog_debug("%s: %s file is empty", __func__,
				   tracker_file->path);
		zebra_tracker_file_set_status(tracker_file,
					      ZEBRA_TRACKER_STATUS_DOWN);
	} else if (line > 1) {
		if (IS_ZEBRA_DEBUG_TRACKER)
			zlog_debug("%s: %s file has more than one line",
				   __func__, tracker_file->path);
		zebra_tracker_file_set_status(tracker_file,
					      ZEBRA_TRACKER_STATUS_DOWN);
	} else if (tracker_file->exact_pattern
		   && strlen(buf) == strlen(tracker_file->pattern)
		   && !strncmp(buf, tracker_file->pattern, strlen(buf))) {
		if (IS_ZEBRA_DEBUG_TRACKER)
			zlog_debug(
				"%s: read %s value on file %s - same as pattern",
				__func__, buf, tracker_file->path);
		zebra_tracker_file_set_status(tracker_file,
					      ZEBRA_TRACKER_STATUS_UP);
	} else if (!tracker_file->exact_pattern
		   && strstr(buf, tracker_file->pattern) != NULL) {
		if (IS_ZEBRA_DEBUG_TRACKER)
			zlog_debug(
				"%s: read %s value on file %s - pattern found",
				__func__, buf, tracker_file->path);
		zebra_tracker_file_set_status(tracker_file,
					      ZEBRA_TRACKER_STATUS_UP);
	} else {
		if (IS_ZEBRA_DEBUG_TRACKER)
			zlog_debug(
				"%s: read %s value on file %s - different from pattern %s",
				__func__, buf, tracker_file->path,
				tracker_file->pattern);
		zebra_tracker_file_set_status(tracker_file,
					      ZEBRA_TRACKER_STATUS_DOWN);
	}

	fclose(file);
}

static void zebra_tracker_notify_file_exist_cb(struct event *event)
{
	struct zebra_tracker_file *tracker_file;
	FILE *file;

	tracker_file = EVENT_ARG(event);

	if ((file = fopen(tracker_file->path, "r"))) {
		fclose(file);
		if (IS_ZEBRA_DEBUG_TRACKER)
			zlog_debug("%s: new file %s has been detected",
				   __func__, tracker_file->path);
		zebra_tracker_notify_file_close(tracker_file);
		zebra_tracker_notify_file_init(tracker_file);
	} else {
		event_add_timer(
			zrouter.master, zebra_tracker_notify_file_exist_cb,
			tracker_file, ZEBRA_TRACKER_FILE_RETRY,
			&tracker_file->event);
	}
	return;
}

static void zebra_tracker_notify_file_event_cb(struct event *event)
{
	struct zebra_tracker_file *tracker_file;
	struct inotify_event *inotif_event;
	char buf[BUFSIZ];
	int fd_monitor;
	ssize_t len;


	fd_monitor = EVENT_FD(event);
	tracker_file = EVENT_ARG(event);

	if (IS_ZEBRA_DEBUG_TRACKER)
		zlog_debug("%s: get an inotify inotif_event fo %s", __func__,
			   tracker_file->path);

	event_add_read(
		zrouter.master, zebra_tracker_notify_file_event_cb,
		tracker_file, fd_monitor, &tracker_file->event);

	len = read(fd_monitor, buf, sizeof(buf));
	if (len < 0) {
		zlog_err("%s: failed to read inotif_event (%s)", __func__,
			 safe_strerror(errno));
		return;
	}
	for (inotif_event = (struct inotify_event *)buf; (char *)inotif_event < &buf[len];
	     inotif_event = (struct inotify_event *)((char *)inotif_event + sizeof(*inotif_event)
					      + inotif_event->len)) {

		if (!(inotif_event->mask & (IN_DELETE_SELF | IN_CLOSE_WRITE)))
			continue;

		if (offsetof(struct inotify_event, name) + inotif_event->len
		    >= sizeof(buf)) {
			zlog_err("%s: failed to read event: buffer underflow",
				 __func__);
			break;
		}

		if (inotif_event->mask & IN_CLOSE_WRITE) {
			if (IS_ZEBRA_DEBUG_TRACKER)
				zlog_debug("%s: get a close_write event for %s",
					   __func__, tracker_file->path);
			zebra_tracker_notify_file_status(tracker_file);
		} else if (inotif_event->mask & IN_DELETE_SELF) {
			if (IS_ZEBRA_DEBUG_TRACKER)
				zlog_debug("%s: get a delete self event for %s",
					   __func__, tracker_file->path);
			zebra_tracker_file_set_status(
				tracker_file, ZEBRA_TRACKER_STATUS_DOWN);
			zebra_tracker_notify_file_close(tracker_file);
			zebra_tracker_notify_file_init(tracker_file);
		}
	}
	return;
}

void zebra_tracker_notify_file_init(struct zebra_tracker_file *tracker_file)
{
	int fd_monitor;

	if (IS_ZEBRA_DEBUG_TRACKER)
		zlog_debug("%s: init %s", __func__, tracker_file->path);

	tracker_file->event = NULL;
	fd_monitor = inotify_init();
	if (fd_monitor < 0) {
		zlog_err("%s: failed to initialize inotify %s (%s)", __func__,
			 tracker_file->path, safe_strerror(errno));
		zebra_tracker_file_set_status(tracker_file,
					      ZEBRA_TRACKER_STATUS_DOWN);
		return;
	}
	if (inotify_add_watch(fd_monitor, tracker_file->path,
			      IN_DELETE_SELF | IN_CLOSE_WRITE)
	    < 0) {
		if (IS_ZEBRA_DEBUG_TRACKER)
			zlog_debug("%s: failed to add watch %s (%s)", __func__,
				   tracker_file->path, safe_strerror(errno));
		zebra_tracker_file_set_status(tracker_file,
					      ZEBRA_TRACKER_STATUS_DOWN);
		event_add_timer(
			zrouter.master, zebra_tracker_notify_file_exist_cb,
			tracker_file, ZEBRA_TRACKER_FILE_RETRY,
			&tracker_file->event);
		return;
	}

	if (IS_ZEBRA_DEBUG_TRACKER)
		zlog_debug("%s: successfully added watch %s", __func__,
			   tracker_file->path);
	zebra_tracker_notify_file_status(tracker_file);

	event_add_read(
		zrouter.master, zebra_tracker_notify_file_event_cb,
		tracker_file, fd_monitor, &tracker_file->event);
}

void zebra_tracker_notify_file_close(struct zebra_tracker_file *tracker_file)
{
	int fd;

	if (tracker_file->event == NULL)
		return;

	if (IS_ZEBRA_DEBUG_TRACKER)
		zlog_debug("%s: close %s", __func__, tracker_file->path);

	fd = EVENT_FD(tracker_file->event);

	EVENT_OFF(tracker_file->event);

	/* auto-removal of notify items */
	if (fd >= 0)
		close(fd);
}
