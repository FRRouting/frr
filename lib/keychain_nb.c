// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * February 22 2024, Christian Hopps <chopps@labn.net>
 *
 * Copyright (C) 2024 LabN Consulting, L.L.C.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include "lib_errors.h"
#include "northbound.h"
#include "keychain.h"

static void keychain_touch(struct keychain *keychain)
{
	keychain->last_touch = time(NULL);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain
 */
static int key_chains_key_chain_create(struct nb_cb_create_args *args)
{
	const char *name;
	struct keychain *keychain;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	keychain = keychain_get(name);
	keychain_touch(keychain);
	return NB_OK;
}

static int key_chains_key_chain_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	keychain_delete(keychain_lookup(name));
	return NB_OK;
}

static const void *key_chains_key_chain_get_next(struct nb_cb_get_next_args *args)
{
	const struct listnode *prev = args->list_entry;

	return prev ? prev->next : keychain_list->head;
}

static int key_chains_key_chain_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct keychain *keychain = node->data;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], keychain->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *key_chains_key_chain_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];
	struct keychain *keychain;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(keychain_list, node, keychain)) {
		if (strcmp(keychain->name, name) == 0)
			return node;
	}
	return NULL;
}


static int __destroy_nop(struct nb_cb_destroy_args *args)
{
	/* modified by sibling or cleaned up by container destroy */
	return NB_OK;
}

static struct key *__dnode_get_key2(const struct lyd_node *dnode, bool touch)
{
	struct keychain *keychain;
	const char *name;
	struct key *key;
	uint32_t index;

	name = yang_dnode_get_string(dnode, "../../../name");
	keychain = keychain_lookup(name);
	index = (uint32_t)yang_dnode_get_uint64(dnode, "../../key-id");
	key = key_lookup(keychain, index);
	if (touch)
		keychain_touch(keychain);
	return key;
}

static struct key *__dnode_get_key3(const struct lyd_node *dnode, bool touch)
{
	struct keychain *keychain;
	const char *name;
	struct key *key;
	uint32_t index;

	name = yang_dnode_get_string(dnode, "../../../../name");
	keychain = keychain_lookup(name);
	index = (uint32_t)yang_dnode_get_uint64(dnode, "../../../key-id");
	key = key_lookup(keychain, index);
	if (touch)
		keychain_touch(keychain);
	return key;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/description
 */
static int key_chains_key_chain_description_modify(struct nb_cb_modify_args *args)
{
	struct keychain *keychain;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	keychain = keychain_lookup(name);
	XFREE(MTYPE_KEYCHAIN_DESC, keychain->desc);
	keychain->desc = XSTRDUP(MTYPE_KEYCHAIN_DESC,
				 yang_dnode_get_string(args->dnode, NULL));

	keychain_touch(keychain);
	return NB_OK;
}

static int key_chains_key_chain_description_destroy(struct nb_cb_destroy_args *args)
{
	struct keychain *keychain;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	keychain = keychain_lookup(name);
	XFREE(MTYPE_KEYCHAIN_DESC, keychain->desc);

	keychain_touch(keychain);
	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/last-modified-timestamp
 */
static struct yang_data *key_chains_key_chain_last_modified_timestamp_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct listnode *kcnode = args->list_entry;
	const struct keychain *keychain = kcnode->data;

	return yang_data_new_date_and_time(args->xpath, keychain->last_touch,
					   false);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key
 */
static int key_chains_key_chain_key_create(struct nb_cb_create_args *args)
{
	struct keychain *keychain;
	struct key *key;
	const char *name;
	uint64_t keyid;

	if (args->event != NB_EV_VALIDATE && args->event != NB_EV_APPLY)
		return NB_OK;

	keyid = yang_dnode_get_uint64(args->dnode, "key-id");
	if (args->event == NB_EV_VALIDATE) {
		if (keyid > UINT32_MAX) {
			/* Warn most protocols can't use this value */
			flog_err(EC_LIB_NB_CB_CONFIG_VALIDATE,
				 "Protocols do not accept > 32-bit key-id values");
			return NB_EV_VALIDATE;
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	keychain = keychain_lookup(name);
	assert(keyid <= UINT32_MAX);
	key = key_get(keychain, (uint32_t)keyid);
	assert(key);

	keychain_touch(keychain);
	return NB_OK;
}

static int key_chains_key_chain_key_destroy(struct nb_cb_destroy_args *args)
{
	struct keychain *keychain;
	struct key *key;
	const char *name;
	uint64_t keyid;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	keyid = yang_dnode_get_uint64(args->dnode, "key-id");
	if (keyid > UINT32_MAX)
		return NB_ERR_NOT_FOUND;
	name = yang_dnode_get_string(args->dnode, "../name");
	keychain = keychain_lookup(name);
	key = key_lookup(keychain, (uint32_t)keyid);
	key_delete(keychain, key);

	keychain_touch(keychain);
	return NB_OK;
}

static const void *key_chains_key_chain_key_get_next(struct nb_cb_get_next_args *args)
{
	const struct listnode *kcnode = args->parent_list_entry;
	const struct keychain *keychain = kcnode->data;
	const struct listnode *prev = args->list_entry;

	return prev ? prev->next : keychain->key->head;
}

static int key_chains_key_chain_key_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct key *key = node->data;

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%" PRIu32,
		 key->index);

	return NB_OK;
}

static const void *key_chains_key_chain_key_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct listnode *kcnode = args->parent_list_entry;
	const struct keychain *keychain = kcnode->data;
	struct listnode *node;
	struct key *key;
	uint32_t index;

	index = strtoul(args->keys->key[0], NULL, 0);
	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key))
		if (key->index == index)
			return node;
	return NULL;
}

static int __lifetime_create(struct nb_cb_create_args *args, bool send,
			     bool accept, bool always)
{
	struct key *key;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (always)
		key = __dnode_get_key3(args->dnode, true);
	else
		key = __dnode_get_key2(args->dnode, true);
	if (send) {
		key->send.start = 0;
		key->send.end = -1;
		key->send.duration = 0;
	}
	if (accept) {
		key->accept.start = 0;
		key->accept.end = -1;
		key->accept.duration = 0;
	}
	return NB_OK;
}

static int __lifetime_start_date_time_modify(struct nb_cb_modify_args *args,
					     bool send, bool accept)
{
	struct key *key;
	time_t time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	key = __dnode_get_key3(args->dnode, true);
	time = yang_dnode_get_date_and_time(args->dnode, NULL);

	if (send)
		key->send.start = time;
	if (accept)
		key->accept.start = time;

	return NB_OK;
}

static int __lifetime_no_end_time_create(struct nb_cb_create_args *args,
					 bool send, bool accept)
{
	struct key *key;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	key = __dnode_get_key3(args->dnode, true);
	if (send)
		key->send.end = -1;
	if (accept)
		key->accept.end = -1;
	return NB_OK;
}

static int __lifetime_duration_modify(struct nb_cb_modify_args *args, bool send,
				      bool accept)
{
	struct key *key;
	uint32_t duration;
	time_t time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	key = __dnode_get_key3(args->dnode, true);
	time = yang_dnode_get_date_and_time(args->dnode, "../start-date-time");
	duration = yang_dnode_get_uint32(args->dnode, NULL);

	if (send)
		key->send.end = time + duration;
	if (accept)
		key->accept.end = time + duration;
	return NB_OK;
}

static int __lifetime_end_date_time_modify(struct nb_cb_modify_args *args,
					   bool send, bool accept)
{
	struct key *key;
	time_t time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	key = __dnode_get_key3(args->dnode, true);
	time = yang_dnode_get_date_and_time(args->dnode, NULL);

	if (send)
		key->send.end = time;
	if (accept)
		key->accept.end = time;
	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime
 */
static int key_chains_key_chain_key_lifetime_send_accept_lifetime_create(
	struct nb_cb_create_args *args)
{

	return __lifetime_create(args, true, true, false);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/always
 */
static int key_chains_key_chain_key_lifetime_send_accept_lifetime_always_create(
	struct nb_cb_create_args *args)
{
	return __lifetime_create(args, true, true, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/start-date-time
 */
static int
key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_modify(
	struct nb_cb_modify_args *args)
{
	return __lifetime_start_date_time_modify(args, true, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/no-end-time
 */
static int
key_chains_key_chain_key_lifetime_send_accept_lifetime_no_end_time_create(
	struct nb_cb_create_args *args)
{
	return __lifetime_no_end_time_create(args, true, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/duration
 */
static int key_chains_key_chain_key_lifetime_send_accept_lifetime_duration_modify(
	struct nb_cb_modify_args *args)
{
	return __lifetime_duration_modify(args, true, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/end-date-time
 */
static int
key_chains_key_chain_key_lifetime_send_accept_lifetime_end_date_time_modify(
	struct nb_cb_modify_args *args)
{
	return __lifetime_end_date_time_modify(args, true, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_create(
	struct nb_cb_create_args *args)
{

	return __lifetime_create(args, true, false, false);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/always
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_always_create(
	struct nb_cb_create_args *args)
{
	return __lifetime_create(args, true, false, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/start-date-time
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_modify(struct nb_cb_modify_args *args)
{
	return __lifetime_start_date_time_modify(args, true, false);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/no-end-time
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_no_end_time_create(struct nb_cb_create_args *args)
{
	return __lifetime_no_end_time_create(args, true, false);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/duration
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_duration_modify(struct nb_cb_modify_args *args)
{
	return __lifetime_duration_modify(args, true, false);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/end-date-time
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_end_date_time_modify(struct nb_cb_modify_args *args)
{
	return __lifetime_end_date_time_modify(args, true, false);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_create(
	struct nb_cb_create_args *args)
{

	return __lifetime_create(args, false, true, false);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/always
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_always_create(struct nb_cb_create_args *args)
{
	return __lifetime_create(args, false, true, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/start-date-time
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_modify(struct nb_cb_modify_args *args)
{
	return __lifetime_start_date_time_modify(args, false, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/no-end-time
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_no_end_time_create(struct nb_cb_create_args *args)
{
	return __lifetime_no_end_time_create(args, false, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/duration
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_duration_modify(struct nb_cb_modify_args *args)
{
	return __lifetime_duration_modify(args, false, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/end-date-time
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_end_date_time_modify(struct nb_cb_modify_args *args)
{
	return __lifetime_end_date_time_modify(args, false, true);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/crypto-algorithm
 */
static int key_chains_key_chain_key_crypto_algorithm_modify(struct nb_cb_modify_args *args)
{
	static const char prefix[] = "ietf-key-chain:";
	static const int prefix_len = sizeof(prefix) - 1;
	struct keychain *keychain;
	const char *name;
	struct key *key;
	uint32_t index;
	uint8_t hash_algo;

	if (args->event != NB_EV_VALIDATE && args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, NULL);
	if (!strncmp(name, prefix, prefix_len))
		name += prefix_len;
	hash_algo = keychain_get_algo_id_by_name(name);

	if (args->event == NB_EV_VALIDATE) {
		if (!hash_algo) {
			zlog_err("\"%s\" hash algo not supported", name);
			return NB_ERR_VALIDATION;
		}
#ifndef CRYPTO_OPENSSL
		if (hash_algo == KEYCHAIN_ALGO_NULL) {
			zlog_err("\"%s\" algo not supported, compile with --with-crypto=openssl",
				 name);
			return NB_ERR_VALIDATION;
		}
#endif /* CRYPTO_OPENSSL */
		return NB_OK;
	}

	assert(args->event == NB_EV_APPLY);
	name = yang_dnode_get_string(args->dnode, "../../name");
	keychain = keychain_lookup(name);
	index = (uint32_t)yang_dnode_get_uint64(args->dnode, "../key-id");
	key = key_lookup(keychain, index);
	key->hash_algo = hash_algo;

	keychain_touch(keychain);
	return NB_OK;
}

static int key_chains_key_chain_key_crypto_algorithm_destroy(
	struct nb_cb_destroy_args *args)
{
	struct keychain *keychain;
	const char *name;
	struct key *key;
	uint32_t index;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../../../name");
	keychain = keychain_lookup(name);
	index = (uint32_t)yang_dnode_get_uint64(args->dnode, "../../key-id");
	key = key_lookup(keychain, index);
	key->hash_algo = KEYCHAIN_ALGO_NULL;
	keychain_touch(keychain);

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/key-string/keystring
 */
static int key_chains_key_chain_key_key_string_keystring_modify(struct nb_cb_modify_args *args)
{
	struct keychain *keychain;
	const char *name;
	struct key *key;
	uint32_t index;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../../../name");
	keychain = keychain_lookup(name);
	index = (uint32_t)yang_dnode_get_uint64(args->dnode, "../../key-id");
	key = key_lookup(keychain, index);
	assert(key);


	if (key->string)
		XFREE(MTYPE_KEY, key->string);
	key->string = XSTRDUP(MTYPE_KEY,
			      yang_dnode_get_string(args->dnode, NULL));

	keychain_touch(keychain);
	return NB_OK;
}

static int key_chains_key_chain_key_key_string_keystring_destroy(struct nb_cb_destroy_args *args)
{
	struct keychain *keychain;
	const char *name;
	struct key *key;
	uint32_t index;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../../../name");
	keychain = keychain_lookup(name);
	index = (uint32_t)yang_dnode_get_uint64(args->dnode, "../../key-id");
	key = key_lookup(keychain, index);
	assert(key);

	XFREE(MTYPE_KEY, key->string);
	keychain_touch(keychain);

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/send-lifetime-active
 */
static struct yang_data *key_chains_key_chain_key_send_lifetime_active_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct key *key = node->data;
	time_t now = time(NULL);
	bool active = false;

	if (key->send.start == 0)
		active = true;
	else if (key->send.start <= now)
		if (key->send.end >= now || key->send.end == -1)
			active = true;

	return yang_data_new_bool(args->xpath, active);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/accept-lifetime-active
 */
static struct yang_data *key_chains_key_chain_key_accept_lifetime_active_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct key *key = node->data;
	time_t now = time(NULL);
	bool active = false;

	if (key->accept.start == 0)
		active = true;
	else if (key->accept.start <= now)
		if (key->accept.end >= now || key->accept.end == -1)
			active = true;

	return yang_data_new_bool(args->xpath, active);
}

static const char * const keychain_features[] = {
	"independent-send-accept-lifetime",
	NULL,
};

/* clang-format off */
const struct frr_yang_module_info ietf_key_chain_info = {
	.name = "ietf-key-chain",
	.features = (const char **)keychain_features,
	.nodes = {
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain",
			.cbs = {
				.create = key_chains_key_chain_create,
				.destroy = key_chains_key_chain_destroy,
				.get_next = key_chains_key_chain_get_next,
				.get_keys = key_chains_key_chain_get_keys,
				.lookup_entry = key_chains_key_chain_lookup_entry,
				.cli_show = key_chains_key_chain_cli_write,
				.cli_show_end = key_chains_key_chain_cli_write_end,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/description",
			.cbs = {
				.modify = key_chains_key_chain_description_modify,
				.destroy = key_chains_key_chain_description_destroy,
				.cli_show = key_chains_key_chain_description_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/last-modified-timestamp",
			.cbs = {
				.get_elem = key_chains_key_chain_last_modified_timestamp_get_elem,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key",
			.cbs = {
				.create = key_chains_key_chain_key_create,
				.destroy = key_chains_key_chain_key_destroy,
				.get_next = key_chains_key_chain_key_get_next,
				.get_keys = key_chains_key_chain_key_get_keys,
				.lookup_entry = key_chains_key_chain_key_lookup_entry,
				.cli_show = key_chains_key_chain_key_cli_write,
				.cli_show_end = key_chains_key_chain_key_cli_write_end,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_accept_lifetime_create,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/always",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_accept_lifetime_always_create,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/start-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_modify,
				.destroy = __destroy_nop,
				.cli_show = key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/no-end-time",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_accept_lifetime_no_end_time_create,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/duration",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_accept_lifetime_duration_modify,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/end-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_accept_lifetime_end_date_time_modify,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_lifetime_create,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/always",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_lifetime_always_create,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/start-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_modify,
				.destroy = __destroy_nop,
				.cli_show = key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/no-end-time",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_lifetime_no_end_time_create,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/duration",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_lifetime_duration_modify,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/end-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_lifetime_end_date_time_modify,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_accept_lifetime_create,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/always",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_accept_lifetime_always_create,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/start-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_modify,
				.destroy = __destroy_nop,
				.cli_show = key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/no-end-time",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_accept_lifetime_no_end_time_create,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/duration",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_accept_lifetime_duration_modify,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/end-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_accept_lifetime_end_date_time_modify,
				.destroy = __destroy_nop,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/crypto-algorithm",
			.cbs = {
				.modify = key_chains_key_chain_key_crypto_algorithm_modify,
				.destroy = key_chains_key_chain_key_crypto_algorithm_destroy,
				.cli_show = key_chains_key_chain_key_crypto_algorithm_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/key-string/keystring",
			.cbs = {
				.modify = key_chains_key_chain_key_key_string_keystring_modify,
				.destroy = key_chains_key_chain_key_key_string_keystring_destroy,
				.cli_show = key_chains_key_chain_key_key_string_keystring_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/send-lifetime-active",
			.cbs = {
				.get_elem = key_chains_key_chain_key_send_lifetime_active_get_elem,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/accept-lifetime-active",
			.cbs = {
				.get_elem = key_chains_key_chain_key_accept_lifetime_active_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	},
};
