#include "debug_wrapper.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

void _logger(void (logfunc(const char *format, ...)), const char *file, const char *func, int line, int e, const char *fmt, ...) {
	char msgbuf[LOGGER_BUFFER_SIZE];

	/*Store the file, line and system error message for the log call*/
	snprintf(msgbuf, LOGGER_BUFFER_SIZE, "[%s:%d] %s: ", file, line, func);

	/*Slurp the format and arguments passed by the user and put them at the
	 * end of the error message */
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(&msgbuf[strnlen(msgbuf, LOGGER_BUFFER_SIZE)], LOGGER_BUFFER_SIZE - strnlen(msgbuf, LOGGER_BUFFER_SIZE), fmt, ap);
	va_end(ap);

	/* Make sure the buffer is NULL terminated */
	msgbuf[LOGGER_BUFFER_SIZE-1] = 0;

	logfunc("%s", msgbuf);
}

void _logger_backtrace(void (logfunc(const char *format, ...)), const char *file, const char *func, int line, int e, const char *fmt, ...) {

	char msgbuf[LOGGER_BUFFER_SIZE];
#ifndef LOGGER_BT_W_VALGRIND
	int n;
	void *bt[LOGGER_BT_SIZE];
#endif

	/*Store the file, line and system error message for the log call*/
	snprintf(msgbuf, LOGGER_BUFFER_SIZE, "[%s:%d] %s: ", file, line, func);

	/*Slurp the format and arguments passed by the user and put them at the
	 * end of the error message */

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(&msgbuf[strnlen(msgbuf, LOGGER_BUFFER_SIZE)], LOGGER_BUFFER_SIZE - strnlen(msgbuf, LOGGER_BUFFER_SIZE), fmt, ap);
	va_end(ap);

	/* Make sure the buffer is NULL terminated */
	msgbuf[LOGGER_BUFFER_SIZE-1] = 0;

	logfunc("%s", msgbuf);

	/* Append Backtrace */
#ifdef LOGGER_BT_W_VALGRIND
	VALGRIND_PRINTF_BACKTRACE("Backtrace:");
#else
	n = backtrace(bt,LOGGER_BT_SIZE);
	backtrace_symbols_fd(bt, n, STDERR_FILENO);
#endif
	fflush(stderr);
}
