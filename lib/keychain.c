// SPDX-License-Identifier: GPL-2.0-or-later
/* key-chain for authentication.
 * Copyright (C) 2000 Kunihiro Ishiguro
 */

#include "config.h"
#include <zebra.h>

#include "keychain.h"
#include "linklist.h"
#include "memory.h"

DEFINE_MTYPE(LIB, KEY, "Key");
DEFINE_MTYPE(LIB, KEYCHAIN, "Key chain");
DEFINE_MTYPE(LIB, KEYCHAIN_DESC, "Key chain description");

DEFINE_QOBJ_TYPE(keychain);
DEFINE_QOBJ_TYPE(key);
DEFINE_HOOK(keychain_removed, (const char *keychain_name), (keychain_name));

/* Master list of key chain. */
struct list *keychain_list;

static struct keychain *keychain_new(void)
{
	struct keychain *keychain;
	keychain = XCALLOC(MTYPE_KEYCHAIN, sizeof(struct keychain));
	QOBJ_REG(keychain, keychain);
	return keychain;
}

static void keychain_free(struct keychain *keychain)
{
	QOBJ_UNREG(keychain);
	XFREE(MTYPE_KEYCHAIN, keychain);
}

static struct key *key_new(void)
{
	struct key *key = XCALLOC(MTYPE_KEY, sizeof(struct key));

	QOBJ_REG(key, key);
	return key;
}

static void key_free(struct key *key)
{
	QOBJ_UNREG(key);
	XFREE(MTYPE_KEY, key);
}

struct keychain *keychain_lookup(const char *name)
{
	struct listnode *node;
	struct keychain *keychain;

	if (name == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(keychain_list, node, keychain)) {
		if (strcmp(keychain->name, name) == 0)
			return keychain;
	}
	return NULL;
}

static int key_cmp_func(void *arg1, void *arg2)
{
	const struct key *k1 = arg1;
	const struct key *k2 = arg2;

	if (k1->index > k2->index)
		return 1;
	if (k1->index < k2->index)
		return -1;
	return 0;
}

static void key_delete_func(struct key *key)
{
	if (key->string)
		XFREE(MTYPE_KEY, key->string);
	key_free(key);
}

struct keychain *keychain_get(const char *name)
{
	struct keychain *keychain;

	keychain = keychain_lookup(name);

	if (keychain)
		return keychain;

	keychain = keychain_new();
	keychain->name = XSTRDUP(MTYPE_KEYCHAIN, name);
	keychain->key = list_new();
	keychain->key->cmp = (int (*)(void *, void *))key_cmp_func;
	keychain->key->del = (void (*)(void *))key_delete_func;
	listnode_add(keychain_list, keychain);

	return keychain;
}

void keychain_delete(struct keychain *keychain)
{
	listnode_delete(keychain_list, keychain);
	/* from now, keychain_lookup() will fail */
	hook_call(keychain_removed, keychain->name);
	list_delete(&keychain->key);
	XFREE(MTYPE_KEYCHAIN, keychain->name);
	keychain_free(keychain);
}

struct key *key_lookup(const struct keychain *keychain, uint32_t index)
{
	struct listnode *node;
	struct key *key;

	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (key->index == index)
			return key;
	}
	return NULL;
}

struct key *key_lookup_for_accept(const struct keychain *keychain,
				  uint32_t index)
{
	struct listnode *node;
	struct key *key;
	time_t now;

	now = time(NULL);

	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (key->index >= index) {
			if (key->accept.start == 0)
				return key;

			if (key->accept.start <= now)
				if (key->accept.end >= now
				    || key->accept.end == -1)
					return key;
		}
	}
	return NULL;
}

struct key *key_match_for_accept(const struct keychain *keychain,
				 const char *auth_str)
{
	struct listnode *node;
	struct key *key;
	time_t now;

	now = time(NULL);

	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (key->accept.start == 0
		    || (key->accept.start <= now
			&& (key->accept.end >= now || key->accept.end == -1)))
			if (key->string && (strncmp(key->string, auth_str, 16) == 0))
				return key;
	}
	return NULL;
}

struct key *key_lookup_for_send(const struct keychain *keychain)
{
	struct listnode *node;
	struct key *key;
	time_t now;

	now = time(NULL);

	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (key->send.start == 0)
			return key;

		if (key->send.start <= now)
			if (key->send.end >= now || key->send.end == -1)
				return key;
	}
	return NULL;
}

/**
 * Find an active key for sending at a specific time.
 *
 * @param keychain The keychain to search within.
 * @param now_ts The current time as a timespec.
 * @return The active key, or NULL if no active key is found.
 */
struct key *keychain_key_find(const struct keychain *keychain, const struct timespec *now_ts)
{
	struct listnode *node;
	struct key *key;
	time_t now_sec;

	if (!keychain || !now_ts)
		return NULL;

	now_sec = now_ts->tv_sec; /* Use seconds part for comparison with time_t lifetimes */

	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (key->send.start == 0 || /* Always valid if start is 0 */
		    (key->send.start <= now_sec &&
		     (key->send.end >= now_sec || key->send.end == (time_t)-1))) /* -1 for infinite */
			return key;
	}
	return NULL;
}

struct key *key_get(const struct keychain *keychain, uint32_t index)
{
	struct key *key;

	key = key_lookup(keychain, index);

	if (key)
		return key;

	key = key_new();
	key->index = index;
	key->hash_algo = KEYCHAIN_ALGO_NULL;
	listnode_add_sort(keychain->key, key);

	return key;
}

void key_delete(struct keychain *keychain, struct key *key)
{
	listnode_delete(keychain->key, key);

	XFREE(MTYPE_KEY, key->string);
	key_free(key);
}

/* clang-format off */

const struct keychain_algo_info algo_info[] = {
	{KEYCHAIN_ALGO_NULL, "null", 0, 0, "NULL"},
	{KEYCHAIN_ALGO_CLEARTEXT, "cleartext", 0, 0, "CLEARTEXT"},
	{KEYCHAIN_ALGO_MD5, "md5", KEYCHAIN_MD5_HASH_SIZE,
	 KEYCHAIN_ALGO_MD5_INTERNAL_BLK_SIZE, "MD5"},
	{KEYCHAIN_ALGO_HMAC_SHA1, "hmac-sha-1", KEYCHAIN_HMAC_SHA1_HASH_SIZE,
	 KEYCHAIN_ALGO_SHA1_INTERNAL_BLK_SIZE, "HMAC-SHA-1"},
	{KEYCHAIN_ALGO_HMAC_SHA256, "hmac-sha-256",
	 KEYCHAIN_HMAC_SHA256_HASH_SIZE, KEYCHAIN_ALGO_SHA256_INTERNAL_BLK_SIZE,
	 "HMAC-SHA-256"},
	{KEYCHAIN_ALGO_HMAC_SHA384, "hmac-sha-384",
	 KEYCHAIN_HMAC_SHA384_HASH_SIZE, KEYCHAIN_ALGO_SHA384_INTERNAL_BLK_SIZE,
	 "HMAC-SHA-384"},
	{KEYCHAIN_ALGO_HMAC_SHA512, "hmac-sha-512",
	 KEYCHAIN_HMAC_SHA512_HASH_SIZE, KEYCHAIN_ALGO_SHA512_INTERNAL_BLK_SIZE,
	 "HMAC-SHA-512"},
	{KEYCHAIN_ALGO_MAX, "max", KEYCHAIN_MAX_HASH_SIZE,
	 KEYCHAIN_ALGO_MAX_INTERNAL_BLK_SIZE, "Not defined"}
};

/* clang-format on */

uint16_t keychain_get_block_size(enum keychain_hash_algo key)
{
	return algo_info[key].block;
}

uint16_t keychain_get_hash_len(enum keychain_hash_algo key)
{
	return algo_info[key].length;
}

const char *keychain_get_description(enum keychain_hash_algo key)
{
	return algo_info[key].desc;
}

struct keychain_algo_info
keychain_get_hash_algo_info(enum keychain_hash_algo key)
{
	return algo_info[key];
}

enum keychain_hash_algo keychain_get_algo_id_by_name(const char *name)
{
#ifdef CRYPTO_INTERNAL
	if (!strncmp(name, "hmac-sha-2", 10))
		return KEYCHAIN_ALGO_HMAC_SHA256;
	else if (!strncmp(name, "md5", 3))
		return KEYCHAIN_ALGO_MD5;
	else if (!strncmp(name, "cleartext", 9))
		return KEYCHAIN_ALGO_CLEARTEXT;
	else
		return KEYCHAIN_ALGO_NULL;
#else
	if (!strncmp(name, "md5", 1))
		return KEYCHAIN_ALGO_MD5;
	else if (!strncmp(name, "cleartext", 9))
		return KEYCHAIN_ALGO_CLEARTEXT;
	else if (!strncmp(name, "hmac-sha-1", 10))
		return KEYCHAIN_ALGO_HMAC_SHA1;
	else if (!strncmp(name, "hmac-sha-2", 10))
		return KEYCHAIN_ALGO_HMAC_SHA256;
	else if (!strncmp(name, "hmac-sha-3", 10))
		return KEYCHAIN_ALGO_HMAC_SHA384;
	else if (!strncmp(name, "hmac-sha-5", 10))
		return KEYCHAIN_ALGO_HMAC_SHA512;
	else
		return KEYCHAIN_ALGO_NULL;
#endif
}

const char *keychain_get_algo_name_by_id(enum keychain_hash_algo key)
{
	return algo_info[key].name;
}

void keychain_terminate(void)
{
	struct keychain *keychain;

	while (listcount(keychain_list)) {
		keychain = listgetdata(listhead(keychain_list));

		listnode_delete(keychain_list, keychain);
		keychain_delete(keychain);
	}

	list_delete(&keychain_list);
}

void keychain_init_new(bool in_backend)
{
	keychain_list = list_new();

	if (!in_backend)
		keychain_cli_init();
}

void keychain_init(void)
{
	keychain_init_new(false);
}

const struct frr_yang_module_info ietf_key_chain_deviation_info = {
	.name = "frr-deviations-ietf-key-chain",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = NULL,
		},
	},
};
