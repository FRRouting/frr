/*
 * clippy (CLI preparator in python) main executable
 * Copyright (C) 2016-2017  David Lamparter for NetDEF, Inc.
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

#include "config.h"
#include <Python.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include "getopt.h"

#include "command_graph.h"
#include "clippy.h"

#if PY_MAJOR_VERSION >= 3
#define pychar wchar_t
static wchar_t *wconv(const char *s)
{
	size_t outlen = s ? mbstowcs(NULL, s, 0) : 0;
	wchar_t *out = malloc((outlen + 1) * sizeof(wchar_t));

	if (outlen > 0)
		mbstowcs(out, s, outlen);
	out[outlen] = 0;
	return out;
}
#else
#define pychar char
#define wconv(x) x
#endif

int main(int argc, char **argv)
{
	pychar **wargv;

#if PY_VERSION_HEX >= 0x03040000 /* 3.4 */
	Py_SetStandardStreamEncoding("UTF-8", NULL);
#endif
	Py_SetProgramName(wconv(argv[0]));
	PyImport_AppendInittab("_clippy", command_py_init);

	Py_Initialize();

	wargv = malloc(argc * sizeof(pychar *));
	for (int i = 1; i < argc; i++)
		wargv[i - 1] = wconv(argv[i]);
	PySys_SetArgv(argc - 1, wargv);

	const char *pyfile = argc > 1 ? argv[1] : NULL;
	FILE *fp;
	if (pyfile) {
		fp = fopen(pyfile, "r");
		if (!fp) {
			fprintf(stderr, "%s: %s\n", pyfile, strerror(errno));
			return 1;
		}
	} else {
		fp = stdin;
		char *ver = strdup(Py_GetVersion());
		char *cr = strchr(ver, '\n');
		if (cr)
			*cr = ' ';
		fprintf(stderr, "clippy interactive shell\n(Python %s)\n", ver);
		free(ver);
		PyRun_SimpleString(
			"import rlcompleter, readline\n"
			"readline.parse_and_bind('tab: complete')");
	}

	if (PyRun_AnyFile(fp, pyfile)) {
		if (PyErr_Occurred())
			PyErr_Print();
		else
			printf("unknown python failure (?)\n");
		return 1;
	}
	Py_Finalize();

#if PY_MAJOR_VERSION >= 3
	for (int i = 1; i < argc; i++)
		free(wargv[i - 1]);
#endif
	free(wargv);
	return 0;
}

/* and now for the ugly part... provide simplified logging functions so we
 * don't need to link libzebra (which would be a circular build dep) */

#ifdef __ASSERT_FUNCTION
#undef __ASSERT_FUNCTION
#endif

#include "log.h"
#include "zassert.h"

#define ZLOG_FUNC(FUNCNAME)                                                    \
	void FUNCNAME(const char *format, ...)                                 \
	{                                                                      \
		va_list args;                                                  \
		va_start(args, format);                                        \
		vfprintf(stderr, format, args);                                \
		fputs("\n", stderr);                                           \
		va_end(args);                                                  \
	}

ZLOG_FUNC(zlog_err)
ZLOG_FUNC(zlog_warn)
ZLOG_FUNC(zlog_info)
ZLOG_FUNC(zlog_notice)
ZLOG_FUNC(zlog_debug)

void _zlog_assert_failed(const char *assertion, const char *file,
			 unsigned int line, const char *function)
{
	fprintf(stderr,
		"Assertion `%s' failed in file %s, line %u, function %s",
		assertion, file, line, (function ? function : "?"));
	abort();
}

void memory_oom(size_t size, const char *name)
{
	abort();
}
