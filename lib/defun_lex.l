/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * clippy (CLI preparator in python) C pseudo-lexer
 * Copyright (C) 2016-2017  David Lamparter for NetDEF, Inc.
 */

/* This is just enough of a lexer to make rough sense of a C source file.
 * It handles C preprocessor directives, strings, and looks for FRR-specific
 * idioms (aka DEFUN).
 *
 * There is some preliminary support for documentation comments for DEFUNs.
 * They would look like this (note the ~):  (replace \ by /)
 *
 * \*~  documentation for foobar_cmd
 *  *   parameter does xyz
 *  *\
 * DEFUN(foobar_cmd, ...)
 *
 * This is intended for user documentation / command reference.  Don't put
 * code documentation in it.
 */

%top{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
}
%{
/* ignore harmless bugs in old versions of flex */
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-value"
#pragma GCC diagnostic ignored "-Wmissing-noreturn"

#include "config.h"
#include <Python.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "command_graph.h"
#include "clippy.h"

#define ID	 258
#define PREPROC	 259
#define OPERATOR 260
#define STRING	 261
#define COMMENT	 262
#define SPECIAL	 263

#define DEFUNNY	  270
#define INSTALL	  271
#define AUXILIARY 272
#define HOOK	  273

int comment_link;
char string_end;
int lno_offs;

char *value, *val_comment;
static const char *yyfilename;
static size_t input_pos;

static void extendbuf(char **what, const char *arg)
{
	if (!*what)
		*what = strdup(arg);
	else {
		size_t vall = strlen(*what), argl = strlen(arg);
		*what = realloc(*what, vall + argl + 1);
		memcpy(*what + vall, arg, argl);
		(*what)[vall + argl] = '\0';
	}
}
#define extend(x)     extendbuf(&value, x)
#define extendcomm(x) extendbuf(&val_comment, x)

#ifndef __clang_analyzer__

static int def_do_input(char *buf, int max_size, FILE *filep)
{
	ssize_t result;

	assert(max_size > 0);

	result = fread(buf, 1, (size_t)max_size, filep);
	if (result >= 0)
		input_pos += result;

	return result;
}

#define YY_INPUT(buf, result, max_size)                                                           \
	do {                                                                                      \
		result = def_do_input(buf, max_size, yyin);                                       \
		if (result < 0)                                                                   \
			YY_FATAL_ERROR("input in flex scanner failed");                           \
	} while (0)

#define YY_USER_INIT BEGIN(linestart)

%}

ID		[A-Za-z0-9_]+
OPERATOR	[!%&/\[\]{}=?:^|\*.;><~'\\+-]
SPECIAL		[(),]

%pointer
%option yylineno
%option noyywrap
%option noinput
%option nounput
%option outfile="lib/defun_lex.c"
%option prefix="def_yy"
%option 8bit

%s linestart
%x comment
%x linecomment
%x preproc
%x rstring

%%

<INITIAL,linestart,preproc>"/*"	comment_link = YY_START; extendcomm(yytext); BEGIN(comment);
<comment>[^*\n]*		extendcomm(yytext);
<comment>"*"+[^*/\n]*		extendcomm(yytext);
<comment>\n			extendcomm(yytext);
<comment>"*"+"/"		extendcomm(yytext); BEGIN(comment_link); if (value) extend(" "); return COMMENT;

<INITIAL,linestart>"//"		extendcomm(yytext); BEGIN(linecomment);
<linecomment>[^\n\\]*		extendcomm(yytext);
<linecomment>\\\n		extendcomm(yytext);
<linecomment>\\			extendcomm(yytext);
<linecomment>\n			BEGIN(linestart); lno_offs = -1; return COMMENT;

<linestart>#			BEGIN(preproc);
<preproc>\n			BEGIN(linestart); return PREPROC;
<preproc>"//"			extendcomm(yytext); BEGIN(linecomment); lno_offs = 1; return PREPROC;
<preproc>[^\n\\/]+		extend(yytext);
<preproc>"/"			extend(yytext);
<preproc>\\\n			extend(yytext);
<preproc>\\+[^\n]		extend(yytext);

[\"\']				string_end = yytext[0]; extend(yytext); BEGIN(rstring);
<rstring>[\"\']			{
					extend(yytext);
					if (yytext[0] == string_end) {
						BEGIN(INITIAL);
						return STRING;
					}
				}
<rstring>\\\n			/* ignore */
<rstring>\n			{
					fprintf(stderr,
						"%s:%d: string continues past the end of the line\n",
						yyfilename, yylineno);
					free(value);
					value = NULL;
					BEGIN(INITIAL);
					return STRING;
				}
<rstring>\\.			extend(yytext);
<rstring>[^\\\"\'\n]+		extend(yytext);

"DEFUN"				value = strdup(yytext); return DEFUNNY;
"DEFUN_ATTR"			value = strdup(yytext); return DEFUNNY;
"DEFUN_NOSH"			value = strdup(yytext); return DEFUNNY;
"DEFUN_HIDDEN"			value = strdup(yytext); return DEFUNNY;
"DEFUN_YANG"			value = strdup(yytext); return DEFUNNY;
"DEFUN_YANG_NOSH"		value = strdup(yytext); return DEFUNNY;
"DEFUN_YANG_HIDDEN"		value = strdup(yytext); return DEFUNNY;
"DEFPY"				value = strdup(yytext); return DEFUNNY;
"DEFPY_NOSH"			value = strdup(yytext); return DEFUNNY;
"DEFPY_ATTR"			value = strdup(yytext); return DEFUNNY;
"DEFPY_HIDDEN"			value = strdup(yytext); return DEFUNNY;
"DEFPY_YANG"			value = strdup(yytext); return DEFUNNY;
"DEFPY_YANG_HIDDEN"		value = strdup(yytext); return DEFUNNY;
"DEFPY_YANG_NOSH"		value = strdup(yytext); return DEFUNNY;
"ALIAS"				value = strdup(yytext); return DEFUNNY;
"ALIAS_ATTR"			value = strdup(yytext); return DEFUNNY;
"ALIAS_HIDDEN"			value = strdup(yytext); return DEFUNNY;
"ALIAS_DEPRECATED"		value = strdup(yytext); return DEFUNNY;
"ALIAS_YANG"			value = strdup(yytext); return DEFUNNY;

"install_element"		value = strdup(yytext); return INSTALL;

"VTYSH_TARGETS"			value = strdup(yytext); return AUXILIARY;
"VTYSH_NODESWITCH"		value = strdup(yytext); return AUXILIARY;

"DO_HOOK"			value = strdup(yytext); return HOOK;
"DEFINE_HOOK"			value = strdup(yytext); return HOOK;
"DECLARE_HOOK"			value = strdup(yytext); return HOOK;
"DO_KOOH"			value = strdup(yytext); return HOOK;
"DEFINE_KOOH"			value = strdup(yytext); return HOOK;
"DECLARE_KOOH"			value = strdup(yytext); return HOOK;

<INITIAL,linestart>\\\n		/* ignore */
[ \t]+				/* ignore */
{ID}				BEGIN(INITIAL); value = strdup(yytext); return ID;
{OPERATOR}			BEGIN(INITIAL); value = strdup(yytext); return OPERATOR;
{SPECIAL}			BEGIN(INITIAL); value = strdup(yytext); return SPECIAL;
\n				BEGIN(linestart);

.				/* printf("-- '%s' in init\n", yytext); */ BEGIN(INITIAL); return yytext[0];

%%

#else
extern int def_yylex(void);
extern int def_yylex_destroy(void);
#endif /* __clang_analyzer__ */

static int yylex_clr(char **retbuf, int *lineno, ssize_t *retpos)
{
	int rv = def_yylex();
	char *yy_ch_buf = YY_CURRENT_BUFFER_LVALUE->yy_ch_buf;

	*retpos = input_pos - yy_n_chars + (yy_c_buf_p - yy_ch_buf);
	if (rv == COMMENT) {
		*retbuf = val_comment;
		val_comment = NULL;
	} else {
		*retbuf = value;
		value = NULL;
	}
	if (lineno)
		*lineno = yylineno + lno_offs;
	lno_offs = 0;
	return rv;
}

static PyObject *get_args(const char *filename, int lineno, ssize_t *off_end)
{
	PyObject *pyObj = PyList_New(0);
	PyObject *pyArg = NULL;

	char *tval;
	int depth = 1;
	int token;

	while ((token = yylex_clr(&tval, NULL, off_end)) != YY_NULL) {
		if (token == SPECIAL && tval[0] == '(') {
			free(tval);
			break;
		}
		if (token == COMMENT) {
			free(tval);
			continue;
		}
		fprintf(stderr, "invalid input!\n");
		exit(1);
	}

	while ((token = yylex_clr(&tval, NULL, off_end)) != YY_NULL) {
		if (token == COMMENT) {
			free(tval);
			continue;
		}
		if (token == PREPROC) {
			free(tval);
			Py_DECREF(pyObj);
			return PyErr_Format(PyExc_ValueError,
					    "%s:%d: cannot process CPP directive within argument list",
					    filename, lineno);
		}
		if (token == SPECIAL) {
			if (depth == 1 && (tval[0] == ',' || tval[0] == ')')) {
				if (pyArg)
					PyList_Append(pyObj, pyArg);
				pyArg = NULL;
				if (tval[0] == ')') {
					free(tval);
					break;
				}
				free(tval);
				continue;
			}
			if (tval[0] == '(')
				depth++;
			if (tval[0] == ')')
				depth--;
		}
		if (!tval)
			return PyErr_Format(PyExc_ValueError,
					    "%s:%d: invalid token in DEFPY parameters", filename,
					    lineno);
		if (!pyArg)
			pyArg = PyList_New(0);
		PyList_Append(pyArg, PyUnicode_FromString(tval));
		free(tval);
	}
	return pyObj;
}

/* _clippy.parse() -- read a C file, returning a list of interesting bits.
 * note this ditches most of the actual C code. */
PyObject *clippy_parse(PyObject *self, PyObject *args)
{
	const char *filename;
	if (!PyArg_ParseTuple(args, "s", &filename))
		return NULL;

	FILE *fd = fopen(filename, "r");
	if (!fd)
		return PyErr_SetFromErrnoWithFilename(PyExc_IOError, filename);

	char *tval;
	int token;

	yyin = fd;
	value = NULL;
	val_comment = NULL;
	yyfilename = filename;
	input_pos = 0;

	PyObject *pyCont = PyDict_New();
	PyObject *pyObj = PyList_New(0);
	PyDict_SetItemString(pyCont, "filename", PyUnicode_FromString(filename));
	PyDict_SetItemString(pyCont, "data", pyObj);

	ssize_t off_start, off_end;
	int lineno;

	while ((token = yylex_clr(&tval, &lineno, &off_start)) != YY_NULL) {
		const char *type;

		PyObject *pyItem = NULL, *pyArgs;
		switch (token) {
		case DEFUNNY:
			if (!(type = "DEFUNNY"))
				/* fallthru */
		case INSTALL:
			if (!(type = "INSTALL"))
				/* fallthru */
		case AUXILIARY:
			if (!(type = "AUXILIARY"))
				/* fallthru */
		case HOOK:
			if (!(type = "HOOK"))
				(void)0;

			off_start -= strlen(tval);

			pyArgs = get_args(filename, lineno, &off_end);
			if (!pyArgs) {
				free(tval);
				Py_DECREF(pyCont);
				yyfilename = NULL;
				return NULL;
			}
			pyItem = PyDict_New();
			PyDict_SetItemString(pyItem, "value", PyUnicode_FromString(tval));
			PyDict_SetItemString(pyItem, "start", PyLong_FromLongLong(off_start));
			PyDict_SetItemString(pyItem, "end", PyLong_FromLongLong(off_end));
			PyDict_SetItemString(pyItem, "type", PyUnicode_FromString(type));
			PyDict_SetItemString(pyItem, "args", pyArgs);
			break;
		case COMMENT:
			if (strncmp(tval, "//~", 3) && strncmp(tval, "/*~", 3))
				break;
			pyItem = PyDict_New();
			PyDict_SetItemString(pyItem, "type", PyUnicode_FromString("COMMENT"));
			PyDict_SetItemString(pyItem, "line", PyUnicode_FromString(tval));
			break;
		case PREPROC:
			pyItem = PyDict_New();
			PyDict_SetItemString(pyItem, "type", PyUnicode_FromString("PREPROC"));
			PyDict_SetItemString(pyItem, "line", PyUnicode_FromString(tval));
			lineno--;
			break;
		}
		if (pyItem) {
			PyDict_SetItemString(pyItem, "lineno", PyLong_FromLong(lineno));
			PyList_Append(pyObj, pyItem);
		}
		free(tval);
	}
	def_yylex_destroy();
	fclose(fd);
	yyfilename = NULL;
	return pyCont;
}
