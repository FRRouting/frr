/*
 * Copyright (c) 2018 Rafael Zalamena <rzalamena@gmail.com>
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

/*
 * Copyright (c) 2016 Rafael Zalamena <rzalamena@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FRR_DB_H_
#define _FRR_DB_H_
#ifdef HAVE_SQLITE3

#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int db_init(const char *path_fmt, ...);
extern int db_close(void);
extern int db_bindf(struct sqlite3_stmt *ss, const char *fmt, ...);
extern struct sqlite3_stmt *db_prepare_len(const char *stmt, int stmtlen);
extern struct sqlite3_stmt *db_prepare(const char *stmt);
extern int db_run(struct sqlite3_stmt *ss);
extern int db_loadf(struct sqlite3_stmt *ss, const char *fmt, ...);
extern void db_finalize(struct sqlite3_stmt **ss);
extern int db_execute(const char *stmt_fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_SQLITE3 */
#endif /* _FRR_DB_H_ */
