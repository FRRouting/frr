// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Server socket program to simulate fpm using protobuf
 * Copyright (C) 2023 Alibaba, Inc.
 *                    Hongyu Li
 */
#include "dplaneserver.h"
#include "zlog.h"
struct option longopts[] = {{ "help", no_argument, NULL, 'h' },
				{ "debug", no_argument, NULL, 'd' },
				{ "file", required_argument, NULL, 'f' },
				{ 0 }};
char *output_file_path;
bool is_ipv6;
bool debug_mode;

void usage(const char *progname, int exit_code)
{
	printf("Usage : %s [OPTION...]\n"
		"-f --file <output file path>\n"
		"-d --debug\n"
		"-i --ipv6\n"
		"-h --help\n",
			progname);
	exit(exit_code);
}
int main(int argc, char **argv)
{
	while (1) {
		int opt;

		opt = getopt_long(argc, argv, "f:dhi", longopts, 0);
		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'f':
			output_file_path = optarg;
			break;
		case 'd':
			debug_mode = true;
			break;
		case 'h':
			usage("dplaneserver", 1);
			break;
		case 'i':
			is_ipv6 = true;
			break;
		default:
			usage("dplaneserver", 1);
			break;
		}
	}
	if (debug_mode)
		zlog_aux_init("DPLANESERVER", LOG_DEBUG);
	else
		zlog_aux_init("DPLANESERVER", LOG_INFO);

	if (output_file_path == NULL) {
		zlog_err("%s: output file path not specified", __func__);
		usage("dplaneserver", 1);
	} else if (access(output_file_path, F_OK) == -1) {
		zlog_err("%s: output file path does not exist", __func__);
		usage("dplaneserver", 1);
	} else {
		if (IS_DPLANE_SERVER_DEBUG)
			zlog_debug("%s: output file path: %s", __func__, output_file_path);
	}

	while (1) {
		int step1 = dplaneserver_init();
		int step2 = dplaneserver_poll();

		if (step2 | step1) {
			if (step2 == -2) {
				if (IS_DPLANE_SERVER_DEBUG)
					zlog_debug("%s: fpm connection closed",
						__func__);
			} else {
				zlog_err("%s: socket errors occur", __func__);
			}
			dplaneserver_exit();
			return 0;
		}
	}
}
