// SPDX-License-Identifier: ISC AND GPL-2.0-or-later
/*
 * Copyright (c) 2018 Rafael Zalamena <rzalamena@gmail.com>
 */

/*
 * Copyright (c) 2016 Rafael Zalamena <rzalamena@gmail.com>
 */

#ifndef _FRR_DB_H_
#define _FRR_DB_H_
#ifdef HAVE_SQLITE3

#include "compiler.h"
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int db_init(const char *path_fmt, ...) PRINTFRR(1, 2);
extern int db_close(void);
/* WARNING: sqlite format string! not printf compatible! */
extern int db_bindf(struct sqlite3_stmt *ss, const char *fmt, ...);
extern struct sqlite3_stmt *db_prepare_len(const char *stmt, int stmtlen);
extern struct sqlite3_stmt *db_prepare(const char *stmt);
extern int db_run(struct sqlite3_stmt *ss);
/* WARNING: sqlite format string! not scanf compatible! */
extern int db_loadf(struct sqlite3_stmt *ss, const char *fmt, ...);
extern void db_finalize(struct sqlite3_stmt **ss);
extern int db_execute(const char *stmt_fmt, ...) PRINTFRR(1, 2);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_SQLITE3 */
#endif /* _FRR_DB_H_ */
