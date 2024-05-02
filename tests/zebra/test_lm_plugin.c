// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Label Manager tests.
 * Copyright (C) 2020 Volta Networks
 *                    Patrick Ruddy
 */


#include <zebra.h>
#include "zebra/zapi_msg.h"
#include "zebra/zebra_router.h"
#include "zebra/label_manager.h"

/* shim out unused functions/variables to allow the lablemanager to compile*/
DEFINE_KOOH(zserv_client_close, (struct zserv * client), (client));
unsigned long zebra_debug_packet = 0;

/* current sysctl platform_labels value */
uint32_t label_manager_platform_value;
/* max label value needed for label input: input labels for swapping and popped labels */
uint32_t label_manager_platform_max_input;
static bool platform_auto; /* configured auto platform_labels */

struct zebra_router zrouter = {
	.multipath_num = MULTIPATH_NUM,
	.ipv4_multicast_mode = MCAST_NO_CONFIG,
};

/*
 * Returns true if label manager controls the
 * mpls max label value to support.
 */
bool zebra_mpls_is_platform_auto_enabled(void)
{
	return platform_auto;
}

void zebra_mpls_platform_labels_update()
{
	uint32_t platform_labels_new;

	platform_labels_new = MPLS_LABEL_MAX;

	if (label_manager_platform_value == platform_labels_new)
		/* no need to update sysctl platform_labels */
		return;

	label_manager_platform_value = platform_labels_new;
}

struct zserv *zserv_find_client_session(uint8_t proto, unsigned short instance,
					uint32_t session_id)
{
	return NULL;
}

int zsend_label_manager_connect_response(struct zserv *client, vrf_id_t vrf_id,
					 unsigned short result)
{
	return 0;
}

int zsend_assign_label_chunk_response(struct zserv *client, vrf_id_t vrf_id,
				      struct label_manager_chunk *lmc)
{
	return 0;
}


int zserv_send_message(struct zserv *client, struct stream *msg)
{
	return 0;
}

void zebra_mpls_static_label_chunk_free_notify(uint32_t label_start,
					       uint32_t size){
	return;
}

static int test_client_connect(struct zserv *client, vrf_id_t vrf_id)
{
	return 0;
}

static int test_client_disconnect(struct zserv *client)
{
	return 0;
}

/* external test hook functions */
static int lm_get_chunk_pi(struct label_manager_chunk **lmc,
			   struct zserv *client, uint8_t keep, uint32_t size,
			   uint32_t base, vrf_id_t vrf_id)
{
	if (base == 0)
		*lmc = create_label_chunk(10, 55, 0, 1, 50, 50 + size, true);
	else
		*lmc = assign_label_chunk(10, 55, 0, 1, size, base);

	return 0;
}

static int lm_release_chunk_pi(struct zserv *client, uint32_t start,
			       uint32_t end)
{
	return release_label_chunk(client->proto, client->instance,
				   client->session_id, start, end);
}


/* use external allocations */
static void lp_plugin_init(void)
{
	/* register our own hooks */
	hook_register(lm_client_connect, test_client_connect);
	hook_register(lm_client_disconnect, test_client_disconnect);
	hook_register(lm_get_chunk, lm_get_chunk_pi);
	hook_register(lm_release_chunk, lm_release_chunk_pi);
}

static void lp_plugin_cleanup(void)
{
	/* register our own hooks */
	hook_unregister(lm_client_connect, test_client_connect);
	hook_unregister(lm_client_disconnect, test_client_disconnect);
	hook_unregister(lm_get_chunk, lm_get_chunk_pi);
	hook_unregister(lm_release_chunk, lm_release_chunk_pi);
}


/* tests */

static void test_lp_plugin(void)
{
	struct label_manager_chunk *lmc;

	lmc = assign_label_chunk(10, 55, 0, 1, 50, 0);
	fprintf(stdout,
		"chunk: start %u end %u proto %u instance %u session %u keep %s\n",
		lmc->start, lmc->end, lmc->proto, lmc->instance,
		lmc->session_id, lmc->keep ? "yes" : "no");
	delete_label_chunk(lmc);

	lmc = assign_label_chunk(10, 55, 0, 1, 50, 100);
	fprintf(stdout,
		"chunk: start %u end %u proto %u instance %u session %u keep %s\n",
		lmc->start, lmc->end, lmc->proto, lmc->instance,
		lmc->session_id, lmc->keep ? "yes" : "no");
	release_label_chunk(10, 55, 0, lmc->start, lmc->end);
}

int main(int argc, char **argv)
{
	/* set up label manager and release it's hooks */
	label_manager_init();
	lm_hooks_unregister();

	/* test plugin */
	lp_plugin_init();
	test_lp_plugin();
	lp_plugin_cleanup();

	/* this keeps the compiler happy */
	hook_call(zserv_client_close, NULL);
	return 0;
}
