/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#include <zebra.h>

#include "libfrr.h"
#include "log.h"
#include "lib_errors.h"
#include "command.h"
#include "db.h"
#include "northbound.h"
#include "northbound_db.h"

int nb_db_init(void)
{
#ifdef HAVE_CONFIG_ROLLBACKS
	/*
	 * NOTE: the delete_tail SQL trigger is used to implement a ring buffer
	 * where only the last N transactions are recorded in the configuration
	 * log.
	 */
	if (db_execute(
		    "BEGIN TRANSACTION;\n"
		    "  CREATE TABLE IF NOT EXISTS transactions(\n"
		    "    client         CHAR(32)             NOT NULL,\n"
		    "    date           DATETIME             DEFAULT CURRENT_TIMESTAMP,\n"
		    "    comment        CHAR(80)             ,\n"
		    "    configuration  TEXT                 NOT NULL\n"
		    "  );\n"
		    "  CREATE TRIGGER IF NOT EXISTS delete_tail\n"
		    "    AFTER INSERT ON transactions\n"
		    "    FOR EACH ROW\n"
		    "    BEGIN\n"
		    "    DELETE\n"
		    "    FROM\n"
		    "      transactions\n"
		    "    WHERE\n"
		    "      rowid%%%u=NEW.rowid%%%u AND rowid!=NEW.rowid;\n"
		    "    END;\n"
		    "COMMIT;",
		    NB_DLFT_MAX_CONFIG_ROLLBACKS, NB_DLFT_MAX_CONFIG_ROLLBACKS)
	    != 0)
		return NB_ERR;
#endif /* HAVE_CONFIG_ROLLBACKS */

	return NB_OK;
}

int nb_db_transaction_save(const struct nb_transaction *transaction,
			   uint32_t *transaction_id)
{
#ifdef HAVE_CONFIG_ROLLBACKS
	struct sqlite3_stmt *ss;
	const char *client_name;
	char *config_str = NULL;
	int ret = NB_ERR;

	/*
	 * Use a transaction to ensure consistency between the INSERT and SELECT
	 * queries.
	 */
	if (db_execute("BEGIN TRANSACTION;") != 0)
		return NB_ERR;

	ss = db_prepare(
		"INSERT INTO transactions\n"
		"  (client, comment, configuration)\n"
		"VALUES\n"
		"  (?, ?, ?);");
	if (!ss)
		goto exit;

	client_name = nb_client_name(transaction->context->client);
	/*
	 * Always record configurations in the XML format, save the default
	 * values too, as this covers the case where defaults may change.
	 */
	if (lyd_print_mem(&config_str, transaction->config->dnode, LYD_XML,
			  LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_ALL)
	    != 0)
		goto exit;

	if (db_bindf(ss, "%s%s%s", client_name, strlen(client_name),
		     transaction->comment, strlen(transaction->comment),
		     config_str ? config_str : "",
		     config_str ? strlen(config_str) : 0)
	    != 0)
		goto exit;

	if (db_run(ss) != SQLITE_OK)
		goto exit;

	db_finalize(&ss);

	/*
	 * transaction_id is an optional output parameter that provides the ID
	 * of the recorded transaction.
	 */
	if (transaction_id) {
		ss = db_prepare("SELECT last_insert_rowid();");
		if (!ss)
			goto exit;

		if (db_run(ss) != SQLITE_ROW)
			goto exit;

		if (db_loadf(ss, "%i", transaction_id) != 0)
			goto exit;

		db_finalize(&ss);
	}

	if (db_execute("COMMIT;") != 0)
		goto exit;

	ret = NB_OK;

exit:
	if (config_str)
		free(config_str);
	if (ss)
		db_finalize(&ss);
	if (ret != NB_OK)
		(void)db_execute("ROLLBACK TRANSACTION;");

	return ret;
#else  /* HAVE_CONFIG_ROLLBACKS */
	return NB_OK;
#endif /* HAVE_CONFIG_ROLLBACKS */
}

struct nb_config *nb_db_transaction_load(uint32_t transaction_id)
{
	struct nb_config *config = NULL;
#ifdef HAVE_CONFIG_ROLLBACKS
	struct lyd_node *dnode;
	const char *config_str;
	struct sqlite3_stmt *ss;
	LY_ERR err;

	ss = db_prepare(
		"SELECT\n"
		"  configuration\n"
		"FROM\n"
		"  transactions\n"
		"WHERE\n"
		"  rowid=?;");
	if (!ss)
		return NULL;

	if (db_bindf(ss, "%d", transaction_id) != 0)
		goto exit;

	if (db_run(ss) != SQLITE_ROW)
		goto exit;

	if (db_loadf(ss, "%s", &config_str) != 0)
		goto exit;

	err = lyd_parse_data_mem(ly_native_ctx, config_str, LYD_XML,
				 LYD_PARSE_STRICT | LYD_PARSE_NO_STATE,
				 LYD_VALIDATE_NO_STATE, &dnode);
	if (err || !dnode)
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_parse_data_mem() failed",
			  __func__);
	else
		config = nb_config_new(dnode);

exit:
	db_finalize(&ss);
#endif /* HAVE_CONFIG_ROLLBACKS */

	return config;
}

int nb_db_clear_transactions(unsigned int n_oldest)
{
#ifdef HAVE_CONFIG_ROLLBACKS
	/* Delete oldest N entries. */
	if (db_execute("DELETE\n"
		       "FROM\n"
		       "  transactions\n"
		       "WHERE\n"
		       "  ROWID IN (\n"
		       "    SELECT\n"
		       "      ROWID\n"
		       "    FROM\n"
		       "      transactions\n"
		       "    ORDER BY ROWID ASC LIMIT %u\n"
		       "  );",
		       n_oldest)
	    != 0)
		return NB_ERR;
#endif /* HAVE_CONFIG_ROLLBACKS */

	return NB_OK;
}

int nb_db_set_max_transactions(unsigned int max)
{
#ifdef HAVE_CONFIG_ROLLBACKS
	/*
	 * Delete old entries if necessary and update the SQL trigger that
	 * auto-deletes old entries.
	 */
	if (db_execute("BEGIN TRANSACTION;\n"
		       "  DELETE\n"
		       "  FROM\n"
		       "    transactions\n"
		       "  WHERE\n"
		       "    ROWID IN (\n"
		       "      SELECT\n"
		       "        ROWID\n"
		       "      FROM\n"
		       "        transactions\n"
		       "      ORDER BY ROWID DESC LIMIT -1 OFFSET %u\n"
		       "    );\n"
		       "  DROP TRIGGER delete_tail;\n"
		       "  CREATE TRIGGER delete_tail\n"
		       "  AFTER INSERT ON transactions\n"
		       "    FOR EACH ROW\n"
		       "    BEGIN\n"
		       "    DELETE\n"
		       "    FROM\n"
		       "      transactions\n"
		       "    WHERE\n"
		       "      rowid%%%u=NEW.rowid%%%u AND rowid!=NEW.rowid;\n"
		       "    END;\n"
		       "COMMIT;",
		       max, max, max)
	    != 0)
		return NB_ERR;
#endif /* HAVE_CONFIG_ROLLBACKS */

	return NB_OK;
}

int nb_db_transactions_iterate(void (*func)(void *arg, int transaction_id,
					    const char *client_name,
					    const char *date,
					    const char *comment),
			       void *arg)
{
#ifdef HAVE_CONFIG_ROLLBACKS
	struct sqlite3_stmt *ss;

	/* Send SQL query and parse the result. */
	ss = db_prepare(
		"SELECT\n"
		"  rowid, client, date, comment\n"
		"FROM\n"
		"  transactions\n"
		"ORDER BY\n"
		"  rowid DESC;");
	if (!ss)
		return NB_ERR;

	while (db_run(ss) == SQLITE_ROW) {
		int transaction_id;
		const char *client_name;
		const char *date;
		const char *comment;
		int ret;

		ret = db_loadf(ss, "%i%s%s%s", &transaction_id, &client_name,
			       &date, &comment);
		if (ret != 0)
			continue;

		(*func)(arg, transaction_id, client_name, date, comment);
	}

	db_finalize(&ss);
#endif /* HAVE_CONFIG_ROLLBACKS */

	return NB_OK;
}
