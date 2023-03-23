// SPDX-License-Identifier: ISC AND GPL-2.0-or-later
/*
 * Copyright (c) 2018 Rafael Zalamena <rzalamena@gmail.com>
 */

/*
 * Copyright (c) 2016 Rafael Zalamena <rzalamena@gmail.com>
 */

#include <zebra.h>

#include "db.h"
#include "log.h"

static struct sqlite3 *dbp;

/*
 * Initialize the database in path.
 *
 * It's possible to use in memory database with ':memory:' path.
 */
int db_init(const char *path_fmt, ...)
{
	char path[BUFSIZ];
	va_list ap;

	if (dbp)
		return -1;

	va_start(ap, path_fmt);
	vsnprintf(path, sizeof(path), path_fmt, ap);
	va_end(ap);

	if (sqlite3_open_v2(path, &dbp,
			    (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE), NULL)
	    != SQLITE_OK) {
		if (dbp == NULL) {
			zlog_warn("%s: failed to open database '%s'", __func__,
				  path);
			return -1;
		}

		zlog_warn("%s: failed to open database '%s': %s", __func__,
			  path, sqlite3_errmsg(dbp));
		if (sqlite3_close_v2(dbp) != SQLITE_OK)
			zlog_warn("%s: failed to terminate database", __func__);
		dbp = NULL;
		return -1;
	}

	return 0;
}

/* Closes the database if open. */
int db_close(void)
{
	if (dbp == NULL)
		return 0;

	if (sqlite3_close_v2(dbp) != SQLITE_OK) {
		zlog_warn("%s: failed to terminate database", __func__);
		return -1;
	}
	return 0;
}

/* Helper function to handle formating. */
static int db_vbindf(struct sqlite3_stmt *ss, const char *fmt, va_list vl)
{
	const char *sptr = fmt;
	int column = 1;
	const char *str;
	void *blob;
	uint64_t uinteger64;
	uint32_t uinteger;
	int vlen;

	while (*sptr) {
		if (*sptr != '%') {
			sptr++;
			continue;
		}
		if (sptr++ && *sptr == 0)
			break;

		switch (*sptr) {
		case 'i':
			uinteger = va_arg(vl, uint32_t);
			if (sqlite3_bind_int(ss, column++, uinteger)
			    != SQLITE_OK)
				return -1;
			break;
		case 'd':
			uinteger64 = va_arg(vl, uint64_t);
			if (sqlite3_bind_int64(ss, column++, uinteger64)
			    != SQLITE_OK)
				return -1;
			break;
		case 's':
			str = va_arg(vl, const char *);
			vlen = va_arg(vl, int);
			if (sqlite3_bind_text(ss, column++, str, vlen,
					      SQLITE_STATIC)
			    != SQLITE_OK)
				return -1;
			break;
		case 'b':
			blob = va_arg(vl, void *);
			vlen = va_arg(vl, int);
			if (sqlite3_bind_blob(ss, column++, blob, vlen,
					      SQLITE_STATIC)
			    != SQLITE_OK)
				return -1;
			break;
		case 'n':
			if (sqlite3_bind_null(ss, column++) != SQLITE_OK)
				return -1;
			break;
		default:
			zlog_warn("%s: invalid format '%c'", __func__, *sptr);
			return -1;
		}
	}

	return 0;
}

/*
 * Binds values using format to the database query.
 *
 * Might be used to bind variables to a query, insert or update.
 */
int db_bindf(struct sqlite3_stmt *ss, const char *fmt, ...)
{
	va_list vl;
	int result;

	va_start(vl, fmt);
	result = db_vbindf(ss, fmt, vl);
	va_end(vl);

	return result;
}

/* Prepares an statement to the database with the statement length. */
struct sqlite3_stmt *db_prepare_len(const char *stmt, int stmtlen)
{
	struct sqlite3_stmt *ss;
	int c;

	if (dbp == NULL)
		return NULL;

	c = sqlite3_prepare_v2(dbp, stmt, stmtlen, &ss, NULL);
	if (ss == NULL) {
		zlog_warn("%s: failed to prepare (%d:%s)", __func__, c,
			  sqlite3_errmsg(dbp));
		return NULL;
	}

	return ss;
}

/* Prepares an statement to the database. */
struct sqlite3_stmt *db_prepare(const char *stmt)
{
	return db_prepare_len(stmt, strlen(stmt));
}

/* Run a prepared statement. */
int db_run(struct sqlite3_stmt *ss)
{
	int result;

	result = sqlite3_step(ss);
	switch (result) {
	case SQLITE_BUSY:
		/* TODO handle busy database. */
		break;

	case SQLITE_OK:
	/*
	 * SQLITE_DONE just causes confusion since it means the query went OK,
	 * but it has a different value.
	 */
	case SQLITE_DONE:
		result = SQLITE_OK;
		break;

	case SQLITE_ROW:
		/* NOTHING */
		/* It is expected to receive SQLITE_ROW on search queries. */
		break;

	default:
		zlog_warn("%s: step failed (%d:%s)", __func__, result,
			  sqlite3_errstr(result));
	}

	return result;
}

/* Helper function to load format to variables. */
static int db_vloadf(struct sqlite3_stmt *ss, const char *fmt, va_list vl)
{
	const char *sptr = fmt;
	int column = 0;
	const char **str;
	void *blob;
	const void *blobsrc;
	uint64_t *uinteger64;
	uint32_t *uinteger;
	int vlen;
	int dlen;
	int columncount;

	columncount = sqlite3_column_count(ss);
	if (columncount == 0)
		return -1;

	while (*sptr) {
		if (*sptr != '%') {
			sptr++;
			continue;
		}
		if (sptr++ && *sptr == 0)
			break;

		switch (*sptr) {
		case 'i':
			uinteger = va_arg(vl, uint32_t *);
			*uinteger = sqlite3_column_int(ss, column);
			break;
		case 'd':
			uinteger64 = va_arg(vl, uint64_t *);
			*uinteger64 = sqlite3_column_int64(ss, column);
			break;
		case 's':
			str = va_arg(vl, const char **);
			*str = (const char *)sqlite3_column_text(ss, column);
			break;
		case 'b':
			blob = va_arg(vl, void *);
			vlen = va_arg(vl, int);
			dlen = sqlite3_column_bytes(ss, column);
			blobsrc = sqlite3_column_blob(ss, column);
			memcpy(blob, blobsrc, MIN(vlen, dlen));
			break;
		default:
			zlog_warn("%s: invalid format '%c'", __func__, *sptr);
			return -1;
		}

		column++;
	}

	return 0;
}

/* Function to load format from database row. */
int db_loadf(struct sqlite3_stmt *ss, const char *fmt, ...)
{
	va_list vl;
	int result;

	va_start(vl, fmt);
	result = db_vloadf(ss, fmt, vl);
	va_end(vl);

	return result;
}

/* Finalize query and return memory. */
void db_finalize(struct sqlite3_stmt **ss)
{
	sqlite3_finalize(*ss);
	*ss = NULL;
}

/* Execute one or more statements. */
int db_execute(const char *stmt_fmt, ...)
{
	char stmt[BUFSIZ];
	va_list ap;

	if (dbp == NULL)
		return -1;

	va_start(ap, stmt_fmt);
	vsnprintf(stmt, sizeof(stmt), stmt_fmt, ap);
	va_end(ap);

	if (sqlite3_exec(dbp, stmt, NULL, 0, NULL) != SQLITE_OK) {
		zlog_warn("%s: failed to execute statement(s): %s", __func__,
			  sqlite3_errmsg(dbp));
		return -1;
	}

	return 0;
}
