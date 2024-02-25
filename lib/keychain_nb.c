// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * XPath: /ietf-key-chain:key-chains/key-chain
 */
static int key_chains_key_chain_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static const void *key_chains_key_chain_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int key_chains_key_chain_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *key_chains_key_chain_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/description
 */
static int key_chains_key_chain_description_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_description_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_description_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/last-modified-timestamp
 */
static struct yang_data *key_chains_key_chain_last_modified_timestamp_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key
 */
static int key_chains_key_chain_key_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static const void *key_chains_key_chain_key_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int key_chains_key_chain_key_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *key_chains_key_chain_key_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/always
 */
static int key_chains_key_chain_key_lifetime_send_accept_lifetime_always_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_accept_lifetime_always_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_accept_lifetime_always_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/start-date-time
 */
static int key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/no-end-time
 */
static int key_chains_key_chain_key_lifetime_send_accept_lifetime_no_end_time_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_accept_lifetime_no_end_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_accept_lifetime_no_end_time_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/duration
 */
static int key_chains_key_chain_key_lifetime_send_accept_lifetime_duration_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_accept_lifetime_duration_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_accept_lifetime_duration_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/end-date-time
 */
static int key_chains_key_chain_key_lifetime_send_accept_lifetime_end_date_time_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_accept_lifetime_end_date_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_accept_lifetime_end_date_time_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/always
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_always_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_lifetime_always_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_lifetime_always_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/start-date-time
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/no-end-time
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_no_end_time_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_lifetime_no_end_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_lifetime_no_end_time_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/duration
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_duration_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_lifetime_duration_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_lifetime_duration_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/end-date-time
 */
static int key_chains_key_chain_key_lifetime_send_lifetime_end_date_time_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_send_lifetime_end_date_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_send_lifetime_end_date_time_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/always
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_always_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_accept_lifetime_always_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_accept_lifetime_always_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/start-date-time
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/no-end-time
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_no_end_time_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_accept_lifetime_no_end_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_accept_lifetime_no_end_time_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/duration
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_duration_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_accept_lifetime_duration_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_accept_lifetime_duration_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/end-date-time
 */
static int key_chains_key_chain_key_lifetime_accept_lifetime_end_date_time_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_lifetime_accept_lifetime_end_date_time_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_lifetime_accept_lifetime_end_date_time_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/crypto-algorithm
 */
static int key_chains_key_chain_key_crypto_algorithm_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_crypto_algorithm_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/key-string/keystring
 */
static int key_chains_key_chain_key_key_string_keystring_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static void key_chains_key_chain_key_key_string_keystring_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static int key_chains_key_chain_key_key_string_keystring_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/send-lifetime-active
 */
static struct yang_data *key_chains_key_chain_key_send_lifetime_active_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/accept-lifetime-active
 */
static struct yang_data *key_chains_key_chain_key_accept_lifetime_active_get_elem(struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/* clang-format off */
const struct frr_yang_module_info ietf_key_chain_nb_info = {
	.name = "ietf-key-chain",
	.nodes = {
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain",
			.cbs = {
				.create = key_chains_key_chain_create,
				.destroy = key_chains_key_chain_destroy,
				.get_next = key_chains_key_chain_get_next,
				.get_keys = key_chains_key_chain_get_keys,
				.lookup_entry = key_chains_key_chain_lookup_entry,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/description",
			.cbs = {
				.modify = key_chains_key_chain_description_modify,
				.destroy = key_chains_key_chain_description_destroy,
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
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/always",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_accept_lifetime_always_create,
				.destroy = key_chains_key_chain_key_lifetime_send_accept_lifetime_always_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/start-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_modify,
				.destroy = key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/no-end-time",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_accept_lifetime_no_end_time_create,
				.destroy = key_chains_key_chain_key_lifetime_send_accept_lifetime_no_end_time_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/duration",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_accept_lifetime_duration_modify,
				.destroy = key_chains_key_chain_key_lifetime_send_accept_lifetime_duration_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/end-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_accept_lifetime_end_date_time_modify,
				.destroy = key_chains_key_chain_key_lifetime_send_accept_lifetime_end_date_time_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/always",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_lifetime_always_create,
				.destroy = key_chains_key_chain_key_lifetime_send_lifetime_always_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/start-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_modify,
				.destroy = key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/no-end-time",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_send_lifetime_no_end_time_create,
				.destroy = key_chains_key_chain_key_lifetime_send_lifetime_no_end_time_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/duration",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_lifetime_duration_modify,
				.destroy = key_chains_key_chain_key_lifetime_send_lifetime_duration_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/end-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_send_lifetime_end_date_time_modify,
				.destroy = key_chains_key_chain_key_lifetime_send_lifetime_end_date_time_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/always",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_accept_lifetime_always_create,
				.destroy = key_chains_key_chain_key_lifetime_accept_lifetime_always_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/start-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_modify,
				.destroy = key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/no-end-time",
			.cbs = {
				.create = key_chains_key_chain_key_lifetime_accept_lifetime_no_end_time_create,
				.destroy = key_chains_key_chain_key_lifetime_accept_lifetime_no_end_time_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/duration",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_accept_lifetime_duration_modify,
				.destroy = key_chains_key_chain_key_lifetime_accept_lifetime_duration_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/end-date-time",
			.cbs = {
				.modify = key_chains_key_chain_key_lifetime_accept_lifetime_end_date_time_modify,
				.destroy = key_chains_key_chain_key_lifetime_accept_lifetime_end_date_time_destroy,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/crypto-algorithm",
			.cbs = {
				.modify = key_chains_key_chain_key_crypto_algorithm_modify,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/key-string/keystring",
			.cbs = {
				.modify = key_chains_key_chain_key_key_string_keystring_modify,
				.destroy = key_chains_key_chain_key_key_string_keystring_destroy,
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
	}
};

/* clang-format off */
const struct frr_yang_module_info ietf_key_chain_cli_info = {
	.name = "ietf-key-chain",
	.nodes = {
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain",
			.cbs = {
				.cli_show = key_chains_key_chain_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/description",
			.cbs = {
				.cli_show = key_chains_key_chain_description_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key",
			.cbs = {
				.cli_show = key_chains_key_chain_key_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/always",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_accept_lifetime_always_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/start-date-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/no-end-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_accept_lifetime_no_end_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/duration",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_accept_lifetime_duration_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/end-date-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_accept_lifetime_end_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/always",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_lifetime_always_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/start-date-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/no-end-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_lifetime_no_end_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/duration",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_lifetime_duration_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/end-date-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_lifetime_end_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/always",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_accept_lifetime_always_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/start-date-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/no-end-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_accept_lifetime_no_end_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/duration",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_accept_lifetime_duration_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/end-date-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_accept_lifetime_end_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/crypto-algorithm",
			.cbs = {
				.cli_show = key_chains_key_chain_key_crypto_algorithm_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/key-string/keystring",
			.cbs = {
				.cli_show = key_chains_key_chain_key_key_string_keystring_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
