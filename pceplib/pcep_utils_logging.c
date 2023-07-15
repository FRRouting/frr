/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include "compiler.h"
#include "pcep_utils_logging.h"

/* Forward declaration */
int pcep_stdout_logger(int priority, const char *format, va_list args)
	PRINTFRR(2, 0);

static pcep_logger_func logger_func = pcep_stdout_logger;
static int logging_level_ = LOG_INFO;

void register_logger(pcep_logger_func logger)
{
	logger_func = logger;
}

void set_logging_level(int level)
{
	logging_level_ = level;
}

int get_logging_level(void)
{
	return logging_level_;
}

void pcep_log(int priority, const char *format, ...)
{
	va_list va;
	va_start(va, format);
	logger_func(priority, format, va);
	va_end(va);
}

void pcep_log_hexbytes(int priority, const char *message, const uint8_t *bytes,
		       uint8_t bytes_len)
{
	char byte_str[2048] = {0};
	int i = 0;

	snprintf(byte_str, 2048, "%s ", message);
	for (; i < bytes_len; i++) {
		snprintf(byte_str, 2048, "%02x ", bytes[i]);
	}
	snprintf(byte_str, 2048, "\n");

	pcep_log(priority, "%s", byte_str);
}

/* Defined with a return type to match the FRR logging signature.
 * Assuming glibc printf() is thread-safe. */
int pcep_stdout_logger(int priority, const char *format, va_list args)
{
	if (priority <= logging_level_) {
		vprintf(format, args);
		printf("\n");
	}

	return 0;
}
