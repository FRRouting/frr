// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#ifndef _FRR_NORTHBOUND_DB_H_
#define _FRR_NORTHBOUND_DB_H_

#include "northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the northbound database.
 *
 * Currently the database is used only for storing and retrieving configuration
 * transactions.
 *
 * Returns:
 *    NB_OK on success, NB_ERR otherwise.
 */
int nb_db_init(void);

/*
 * Save a configuration transaction in the northbound database.
 *
 * transaction
 *    Configuration transaction to be saved.
 *
 * transaction_id
 *    Output parameter providing the ID of the saved transaction.
 *
 * Returns:
 *    NB_OK on success, NB_ERR otherwise.
 */
int nb_db_transaction_save(const struct nb_transaction *transaction,
			   uint32_t *transaction_id);

/*
 * Load a configuration transaction from the transactions log.
 *
 * transaction_id
 *    ID of the transaction to be loaded.
 *
 * Returns:
 *    Pointer to newly created configuration or NULL in the case of an error.
 */
extern struct nb_config *nb_db_transaction_load(uint32_t transaction_id);

/*
 * Delete the specified number of transactions from the transactions log.
 *
 * n_oldest
 *    Number of transactions to delete.
 *
 * Returns:
 *    NB_OK on success, NB_ERR otherwise.
 */
extern int nb_db_clear_transactions(unsigned int n_oldest);

/*
 * Specify the maximum number of transactions we want to record in the
 * transactions log. Note that older transactions can be removed during this
 * operation.
 *
 * max
 *    New upper limit of maximum transactions to log.
 *
 * Returns:
 *    NB_OK on success, NB_ERR otherwise.
 */
extern int nb_db_set_max_transactions(unsigned int max);

/*
 * Iterate over all configuration transactions stored in the northbound
 * database, sorted in descending order.
 *
 * func
 *    Function to call with each configuration transaction.
 *
 * arg
 *    Arbitrary argument passed as the first parameter in each call to 'func'.
 *
 * Returns:
 *    NB_OK on success, NB_ERR otherwise.
 */
extern int nb_db_transactions_iterate(
	void (*func)(void *arg, int transaction_id, const char *client_name,
		     const char *date, const char *comment),
	void *arg);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_NORTHBOUND_DB_H_ */
