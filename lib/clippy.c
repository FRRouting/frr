// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * clippy (CLI preparator in python) main executable
 * Copyright (C) 2016-2017  David Lamparter for NetDEF, Inc.
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
	wchar_t *name = wconv(argv[0]);
	Py_SetProgramName(name);
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

			free(name);
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

		free(name);
		return 1;
	}
	Py_Finalize();

#if PY_MAJOR_VERSION >= 3
	for (int i = 1; i < argc; i++)
		free(wargv[i - 1]);
#endif
	free(name);
	free(wargv);
	return 0;
}

/* and now for the ugly part... provide simplified logging functions so we
 * don't need to link libzebra (which would be a circular build dep) */

#include "log.h"

PRINTFRR(3, 0)
void vzlogx(const struct xref_logmsg *xref, int prio,
	    const char *format, va_list args)
{
	vfprintf(stderr, format, args);
	fputs("\n", stderr);
}

void memory_oom(size_t size, const char *name)
{
	abort();
}
