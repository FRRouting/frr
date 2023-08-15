#include <cstring>
#include <iostream>
#include <inttypes.h>
#include "fpmlink.h"
#include "fpmparser.h"
#include "zlog.h"
#include <getopt.h>
#include <netlink/route/route.h>
#include <string>

using namespace std;


struct option longopts[] = { { "help", no_argument, NULL, 'h' },
			     { "debug", no_argument, NULL, 'd' },
			     { "file", required_argument, NULL, 'f' },
			     { 0 } };

Fpmparser *global_parser = nullptr;

void usage(const char *progname, int exit_code)
{
	printf("Usage : %s [OPTION...]\n\
	-f --file <output file path>\n\
	-d --debug\n\
	-h --help\n",
	       progname);
	exit(exit_code);
}

int main(int argc, char **argv)
{
	bool debug_mode = false;
	char *output_file_path = NULL;
	while (1) {
		int opt;
		opt = getopt_long(argc, argv, "f:dh", longopts, 0);

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
			usage("fpmsyncd", 1);
			break;
		default:
			usage("fpmsyncd", 1);
			break;
		}
	}


	if (debug_mode) {
		zlog_aux_init("FPMSYNCD", LOG_DEBUG);
		zlog_info("Log level set to debug");
	} else {
		zlog_aux_init("FPMSYNCD", LOG_INFO);
		zlog_info("Log level set to info");
	}


	zlog_info("FPMSYNCD starting");
	if (output_file_path == NULL) {
		zlog_err("Output file path not specified");
		usage("fpmsyncd", 1);
	} else if (access(output_file_path, F_OK) == -1) {
		zlog_err("Output file path:%s does not exist", output_file_path);
		usage("fpmsyncd", 1);
	} else {
		if (output_file_path[strlen(output_file_path) - 1] == '/')
			strcat(output_file_path, "routes.json");
		else
			strcat(output_file_path, "/routes.json");
		// clear file
		zlog_info("Clearing file %s", output_file_path);
		std::ofstream(output_file_path,
			      std::ofstream::out | std::ofstream::trunc);
		zlog_info("Output file path: %s", output_file_path);
	}

	/* Init routesync */
	Fpmparser paser(output_file_path);
	global_parser = &paser;


	while (true) {
		try {
			/* Init Fpmlink */
			FpmLink fpm;

			zlog_info("Waiting for fpm-client connection...");


			// fpm.accept();

			fpm.epoll();


		} catch (FpmLink::FpmConnectionClosedException &e) {
			zlog_err("Connection lost, reconnecting...");
		} catch (const exception &e) {
			zlog_err("Exception \"%s\" had been thrown in daemon",
				 e.what());
			return 0;
		}
	}

	return 1;
}
