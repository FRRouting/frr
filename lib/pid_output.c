// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Process id output.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 */

#include <zebra.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <log.h>
#include "lib/version.h"
#include "network.h"
#include "lib_errors.h"

#define PIDFILE_MASK 0644

pid_t pid_output(const char *path)
{
	int tmp;
	int fd;
	pid_t pid;
	char buf[16];
	struct flock lock;
	mode_t oldumask;

	pid = getpid();

	oldumask = umask(0777 & ~PIDFILE_MASK);
	fd = open(path, O_RDWR | O_CREAT, PIDFILE_MASK);
	if (fd < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "Can't create pid lock file %s (%s), exiting",
			     path, safe_strerror(errno));
		umask(oldumask);
		exit(1);
	} else {
		size_t pidsize;

		umask(oldumask);
		memset(&lock, 0, sizeof(lock));

		set_cloexec(fd);

		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;

		if (fcntl(fd, F_SETLK, &lock) < 0) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "Could not lock pid_file %s (%s), exiting.  Please ensure that the daemon is not already running",
				     path, safe_strerror(errno));
			exit(1);
		}

		snprintf(buf, sizeof(buf), "%d\n", (int)pid);
		pidsize = strlen(buf);
		if ((tmp = write(fd, buf, pidsize)) != (int)pidsize)
			flog_err_sys(
				EC_LIB_SYSTEM_CALL,
				"Could not write pid %d to pid_file %s, rc was %d: %s",
				(int)pid, path, tmp, safe_strerror(errno));
		else if (ftruncate(fd, pidsize) < 0)
			flog_err_sys(
				EC_LIB_SYSTEM_CALL,
				"Could not truncate pid_file %s to %u bytes: %s",
				path, (unsigned int)pidsize,
				safe_strerror(errno));
	}
	return pid;
}
