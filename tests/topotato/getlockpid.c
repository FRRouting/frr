/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2022  David Lamparter for NetDEF, Inc.
 */

/* simple short tool to get PID of process locking file.
 * used in topotato because python does not provide access to this
 * functionality, and "struct flock" is very OS-dependent (could use
 * struct.pack/unpack otherwise)
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	int fd, res;
	struct flock lk;

	if (argc != 2) {
		fprintf(stderr, "usage: %s FILENAME\n", argv[0]);
		exit(1);
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror(argv[1]);
		exit(1);
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;
	lk.l_pid = -1;

	res = fcntl(fd, F_GETLK, &lk);
	close(fd);

	if (res) {
		perror("fcntl");
		exit(1);
	}
	if (lk.l_type == F_UNLCK) {
		fprintf(stderr, "%s not locked\n", argv[1]);
		exit(2);
	}

	printf("%lld", (long long)lk.l_pid);
	return 0;
}
