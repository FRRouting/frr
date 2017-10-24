/*
 *
 * Copyright 2015-2016, LabN Consulting, L.L.C.
 *
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

/* stub rfp */
#include "rfp_internal.h"
#include "bgpd/rfapi/rfapi.h"
#include "lib/command.h"

struct rfp_instance_t {
	struct rfapi_rfp_cfg rfapi_config;
	struct rfapi_rfp_cb_methods rfapi_callbacks;
	struct thread_master *master;
	uint32_t config_var;
};

struct rfp_instance_t
	global_rfi; /* dynamically allocate in full implementation */

/***********************************************************************
 * Sample VTY / internal function
 **********************************************************************/
#define RFP_SHOW_STR "RFP information\n"
DEFUN (rfp_example_config_value,
       rfp_example_config_value_cmd,
       "rfp example-config-value VALUE",
       RFP_SHOW_STR
       "Example value to be configured\n"
       "Value to display\n")
{
	uint32_t value = 0;
	struct rfp_instance_t *rfi = NULL;
	rfi = rfapi_get_rfp_start_val(VTY_GET_CONTEXT(bgp)); /* BGP_NODE */
	assert(rfi != NULL);

	value = strtoul(argv[2]->arg, NULL, 10);
	if (rfi)
		rfi->config_var = value;
	return CMD_SUCCESS;
}

static void rfp_vty_install()
{
	static int installed = 0;
	if (installed) /* do this only once */
		return;
	installed = 1;
	/* example of new cli command */
	install_element(BGP_NODE, &rfp_example_config_value_cmd);
}

/***********************************************************************
 * RFAPI Callbacks
 **********************************************************************/

/*------------------------------------------
 * rfp_response_cb
 *
 * Callbacks of this type are used to provide asynchronous
 * route updates from RFAPI to the RFP client.
 *
 * response_cb
 *	called to notify the rfp client that a next hop list
 *	that has previously been provided in response to an
 *	rfapi_query call has been updated. Deleted routes are indicated
 *	with lifetime==RFAPI_REMOVE_RESPONSE_LIFETIME.
 *
 *	By default, the routes an NVE receives via this callback include
 *	its own routes (that it has registered). However, these may be
 *	filtered out if the global BGP_VNC_CONFIG_FILTER_SELF_FROM_RSP
 *	flag is set.
 *
 * input:
 *	next_hops	a list of possible next hops.
 *			This is a linked list allocated within the
 *			rfapi. The response_cb callback function is responsible
 *			for freeing this memory via rfapi_free_next_hop_list()
 *			in order to avoid memory leaks.
 *
 *	userdata	value (cookie) originally specified in call to
 *			rfapi_open()
 *
 *------------------------------------------*/
static void rfp_response_cb(struct rfapi_next_hop_entry *next_hops,
			    void *userdata)
{
	/*
	 * Identify NVE based on userdata, which is a value passed
	 * to RFAPI in the rfapi_open call
	 */

	/* process list of next_hops */

	/* free next hops */
	rfapi_free_next_hop_list(next_hops);
	return;
}

/*------------------------------------------
 * rfp_local_cb
 *
 * Callbacks of this type are used to provide asynchronous
 * route updates from RFAPI to the RFP client.
 *
 * local_cb
 *	called to notify the rfp client that a local route
 *	has been added or deleted. Deleted routes are indicated
 *	with lifetime==RFAPI_REMOVE_RESPONSE_LIFETIME.
 *
 * input:
 *	next_hops	a list of possible next hops.
 *			This is a linked list allocated within the
 *			rfapi. The local_cb callback function is responsible
 *			for freeing this memory via rfapi_free_next_hop_list()
 *			in order to avoid memory leaks.
 *
 *	userdata	value (cookie) originally specified in call to
 *			rfapi_open()
 *
 *------------------------------------------*/
static void rfp_local_cb(struct rfapi_next_hop_entry *next_hops, void *userdata)
{
	/*
	 * Identify NVE based on userdata, which is a value passed
	 * to RFAPI in the rfapi_open call
	 */

	/* process list of local next_hops */

	/* free next hops */
	rfapi_free_next_hop_list(next_hops);
	return;
}

/*------------------------------------------
 * rfp_close_cb
 *
 * Callbacks used to provide asynchronous
 * notification that an rfapi_handle was invalidated
 *
 * input:
 *	pHandle		Firmerly valid rfapi_handle returned to
 *			client via rfapi_open().
 *
 *	reason		EIDRM	handle administratively closed (clear nve ...)
 *			ESTALE	handle invalidated by configuration change
 *
 *------------------------------------------*/
static void rfp_close_cb(rfapi_handle pHandle, int reason)
{
	/* close / invalidate NVE with the pHandle returned by the rfapi_open
	 * call */
	return;
}

/*------------------------------------------
 * rfp_cfg_write_cb
 *
 * This callback is used to generate output for any config parameters
 * that may supported by RFP  via RFP defined vty commands at the bgp
 * level.  See loglevel as an example.
 *
 * input:
 *    vty           -- quagga vty context
 *    rfp_start_val -- value returned by rfp_start
 *
 * output:
 *    to vty, rfp related configuration
 *
 * return value:
 *    lines written
--------------------------------------------*/
static int rfp_cfg_write_cb(struct vty *vty, void *rfp_start_val)
{
	struct rfp_instance_t *rfi = rfp_start_val;
	int write = 0;
	assert(rfp_start_val != NULL);
	if (rfi->config_var != 0) {
		vty_out(vty, " rfp example-config-value %u", rfi->config_var);
		vty_out(vty, "\n");
		write++;
	}

	return write;
}

/***********************************************************************
 * RFAPI required functions
 **********************************************************************/

/*------------------------------------------
 * rfp_start
 *
 * This function will start the RFP code
 *
 * input:
 *    master    quagga thread_master to tie into bgpd threads
 *
 * output:
 *    cfgp      Pointer to rfapi_rfp_cfg (null = use defaults),
 *              copied by caller, updated via rfp_set_configuration
 *    cbmp      Pointer to rfapi_rfp_cb_methods, may be null
 *              copied by caller, updated via rfapi_rfp_set_cb_methods
 *
 * return value:
 *    rfp_start_val rfp returned value passed on rfp_stop and rfp_cfg_write
 *
--------------------------------------------*/
void *rfp_start(struct thread_master *master, struct rfapi_rfp_cfg **cfgp,
		struct rfapi_rfp_cb_methods **cbmp)
{
	memset(&global_rfi, 0, sizeof(struct rfp_instance_t));
	global_rfi.master = master; /* for BGPD threads */

	/* initilize struct rfapi_rfp_cfg, see rfapi.h */
	global_rfi.rfapi_config.download_type =
		RFAPI_RFP_DOWNLOAD_FULL; /* default=partial */
	global_rfi.rfapi_config.ftd_advertisement_interval =
		RFAPI_RFP_CFG_DEFAULT_FTD_ADVERTISEMENT_INTERVAL;
	global_rfi.rfapi_config.holddown_factor =
		0; /* default: RFAPI_RFP_CFG_DEFAULT_HOLDDOWN_FACTOR */
	global_rfi.rfapi_config.use_updated_response = 1; /* 0=no */
	global_rfi.rfapi_config.use_removes = 1;	  /* 0=no */


	/* initilize structrfapi_rfp_cb_methods , see rfapi.h */
	global_rfi.rfapi_callbacks.cfg_cb = rfp_cfg_write_cb;
	/* no group config */
	global_rfi.rfapi_callbacks.response_cb = rfp_response_cb;
	global_rfi.rfapi_callbacks.local_cb = rfp_local_cb;
	global_rfi.rfapi_callbacks.close_cb = rfp_close_cb;

	if (cfgp != NULL)
		*cfgp = &global_rfi.rfapi_config;
	if (cbmp != NULL)
		*cbmp = &global_rfi.rfapi_callbacks;

	rfp_vty_install();

	return &global_rfi;
}

/*------------------------------------------
 * rfp_stop
 *
 * This function is called on shutdown to trigger RFP cleanup
 *
 * input:
 *    none
 *
 * output:
 *    none
 *
 * return value:
 *    rfp_start_val
--------------------------------------------*/
void rfp_stop(void *rfp_start_val)
{
	assert(rfp_start_val != NULL);
}

/* TO BE REMOVED */
void rfp_clear_vnc_nve_all(void)
{
	return;
}
