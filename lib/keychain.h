// SPDX-License-Identifier: GPL-2.0-or-later
/* key-chain for authentication.
 * Copyright (C) 2000 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_KEYCHAIN_H
#define _ZEBRA_KEYCHAIN_H

#include "memory.h"
#include "northbound.h"
#include "qobj.h"

#ifdef __cplusplus
extern "C" {
#endif

enum keychain_hash_algo {
	KEYCHAIN_ALGO_NULL,
	KEYCHAIN_ALGO_MD5,
	KEYCHAIN_ALGO_HMAC_SHA1,
	KEYCHAIN_ALGO_HMAC_SHA256,
	KEYCHAIN_ALGO_HMAC_SHA384,
	KEYCHAIN_ALGO_HMAC_SHA512,
	KEYCHAIN_ALGO_MAX
};

#define KEYCHAIN_MD5_HASH_SIZE 16
#define KEYCHAIN_HMAC_SHA1_HASH_SIZE 20
#define KEYCHAIN_HMAC_SHA256_HASH_SIZE 32
#define KEYCHAIN_HMAC_SHA384_HASH_SIZE 48
#define KEYCHAIN_HMAC_SHA512_HASH_SIZE 64
#define KEYCHAIN_MAX_HASH_SIZE 64

#define KEYCHAIN_ALGO_MD5_INTERNAL_BLK_SIZE 16
#define KEYCHAIN_ALGO_SHA1_INTERNAL_BLK_SIZE 64
#define KEYCHAIN_ALGO_SHA256_INTERNAL_BLK_SIZE 64
#define KEYCHAIN_ALGO_SHA384_INTERNAL_BLK_SIZE 128
#define KEYCHAIN_ALGO_SHA512_INTERNAL_BLK_SIZE 128
#define KEYCHAIN_ALGO_MAX_INTERNAL_BLK_SIZE 128

struct keychain_algo_info {
	enum keychain_hash_algo key;
	const char *name;
	uint16_t length;
	uint16_t block;
	const char *desc;
};

extern const struct frr_yang_module_info ietf_key_chain_info;
extern const struct frr_yang_module_info ietf_key_chain_cli_info;
extern const struct frr_yang_module_info ietf_key_chain_deviation_info;

extern const struct keychain_algo_info algo_info[];
uint16_t keychain_get_block_size(enum keychain_hash_algo key);
uint16_t keychain_get_hash_len(enum keychain_hash_algo key);
const char *keychain_get_description(enum keychain_hash_algo key);
struct keychain_algo_info
keychain_get_hash_algo_info(enum keychain_hash_algo key);
enum keychain_hash_algo keychain_get_algo_id_by_name(const char *name);
const char *keychain_get_algo_name_by_id(enum keychain_hash_algo key);

struct keychain {
	char *name;
	char *desc;
	time_t last_touch;

	struct list *key;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(keychain);

struct key_range {
	time_t start;
	time_t end;

	uint8_t duration;
};

struct key {
	uint32_t index;

	char *string;
	enum keychain_hash_algo hash_algo;
	struct key_range send;
	struct key_range accept;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(key);

DECLARE_MTYPE(KEY);
DECLARE_MTYPE(KEYCHAIN);
DECLARE_MTYPE(KEYCHAIN_DESC);

/* keychain implementation */
extern struct list *keychain_list;
struct keychain *keychain_lookup(const char *name);
struct keychain *keychain_get(const char *name);
void keychain_delete(struct keychain *keychain);
struct key *key_lookup(const struct keychain *keychain, uint32_t index);
struct key *key_get(const struct keychain *keychain, uint32_t index);
void key_delete(struct keychain *keychain, struct key *key);

void keychain_cli_init(void);
extern void key_chains_key_chain_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
extern void key_chains_key_chain_cli_write_end(struct vty *vty, const struct lyd_node *dnode);
extern void key_chains_key_chain_description_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void key_chains_key_chain_key_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
extern void key_chains_key_chain_key_cli_write_end(struct vty *vty, const struct lyd_node *dnode);
extern void key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
extern void key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
extern void key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
extern void key_chains_key_chain_key_crypto_algorithm_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
extern void key_chains_key_chain_key_key_string_keystring_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

/* keychain users */
extern void keychain_init(void);
extern void keychain_init_new(bool in_backend);
extern void keychain_terminate(void);
extern struct keychain *keychain_lookup(const char *);
extern struct key *key_lookup_for_accept(const struct keychain *, uint32_t);
extern struct key *key_match_for_accept(const struct keychain *, const char *);
extern struct key *key_lookup_for_send(const struct keychain *);
const char *keychain_algo_str(enum keychain_hash_algo hash_algo);



#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_KEYCHAIN_H */
