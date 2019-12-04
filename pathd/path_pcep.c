/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sebastien Merle
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

#include "log.h"
#include "command.h"
#include "debug.h"
#include "libfrr.h"
#include "printfrr.h"
#include "version.h"
#include "northbound.h"
#include "frr_pthread.h"

#include "pathd/path_errors.h"
#include "pathd/path_memory.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_debug.h"

#define PCEP_DEFAULT_PORT 4189
#define POLL_INTERVAL 1

#define PCEP_DEBUG(fmt, ...) DEBUGD(&pcep_g->dbg, fmt, ##__VA_ARGS__)

DEFINE_MTYPE(PATHD, PCEP, "PCEP module")

/*
 * Globals.
 */
typedef struct pcep_glob_t_ {
	struct debug dbg;
	struct thread_master *master;
	struct frr_pthread *fpt;
} pcep_glob_t;

static pcep_glob_t pcep_glob_space = { .dbg = {0, "pathd module: pcep"} };
static pcep_glob_t *pcep_g = &pcep_glob_space;

/* PCC Functions */
static pcc_state_t* pcep_pcc_initialize(ctrl_state_t *ctrl_state, int index);
static void pcep_pcc_finalize(ctrl_state_t *ctrl_state, pcc_state_t *pcc_state);
static int pcep_pcc_update(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state,
			   pcc_opts_t *opts);
static int pcep_pcc_enable(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state);
static int pcep_pcc_disable(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state);
static void pcep_pcc_handle_pcep_event(ctrl_state_t *ctrl_state,
				       pcc_state_t * pcc_state,
				       pcep_event *event);
static void pcep_pcc_synchronize(ctrl_state_t *ctrl_state,
				 pcc_state_t * pcc_state);
static void pcep_pcc_handle_message(ctrl_state_t *ctrl_state,
				    pcc_state_t * pcc_state, pcep_message *msg);
static void pcep_pcc_lsp_update(ctrl_state_t *ctrl_state,
				pcc_state_t * pcc_state, pcep_message *msg);
static void pcep_pcc_lsp_initiate(ctrl_state_t *ctrl_state,
				  pcc_state_t * pcc_state, pcep_message *msg);
static void pcep_pcc_send(ctrl_state_t *ctrl_state,
			  pcc_state_t * pcc_state, pcep_message *msg);

/* Controller Functions Called from Main */
static int pcep_controller_initialize(void);
static int pcep_controller_finalize(void);
static int pcep_controller_pcc_update(int index, pcc_opts_t *opts);
static int pcep_controller_pcc_disconnect(int index);
static int pcep_halt_cb(struct frr_pthread *fpt, void **res);

/* Controller Functions Called From Thread */
#if 0
static void pcep_thread_start_sync(ctrl_state_t *ctrl_state);
static void pcep_thread_update_lsp(ctrl_state_t *ctrl_state);
#endif
static void pcep_thread_schedule_poll(ctrl_state_t *ctrl_state);
static int pcep_thread_init_event(struct thread *thread);
static int pcep_thread_finish_event(struct thread *thread);
static int pcep_thread_poll_timer(struct thread *thread);
static int pcep_thread_pcc_update_event(struct thread *thread);
static int pcep_thread_pcc_disconnect_event(struct thread *thread);

/* Main Thread Functions */
#if 0
static int pcep_main_start_sync_event(struct thread *thread);
static int pcep_main_update_lsp_event(struct thread *thread);
#endif

/* CLI Functions */
static int pcep_cli_debug_config_write(struct vty *vty);
static int pcep_cli_debug_set_all(uint32_t flags, bool set);
static void pcep_cli_init(void);

/* Module Functions */
static int pcep_module_finish(void);
static int pcep_module_late_init(struct thread_master *tm);
static int pcep_module_init(void);


/* Should be in path_pcep_lib.[ch] */

static int pcep_lib_connect(pcc_state_t *pcc_state);
static void pcep_lib_disconnect(pcc_state_t *pcc_state);
static double_linked_list *pcep_lib_format_path(path_t *path);
static path_t *pcep_lib_parse_path(double_linked_list *objs);
static void pcep_lib_free_path(path_t *path);

static void pcep_lib_parse_srp(path_t *path, struct pcep_object_srp* srp);
static void pcep_lib_parse_lsp(path_t *path, struct pcep_object_lsp* lsp);
static void pcep_lib_parse_ero(path_t *path, struct pcep_object_ro* ero);

int pcep_lib_connect(pcc_state_t *pcc_state)
{
	assert(NULL != pcc_state);
	assert(NULL != pcc_state->opts);
	assert(NULL == pcc_state->config);
	assert(NULL == pcc_state->sess);

	pcep_configuration *config;
	pcep_session *sess;

	config = create_default_pcep_configuration();
	config->support_stateful_pce_lsp_update = true;
	config->support_sr_te_pst = true;
	config->use_pcep_sr_draft07 = true;
	//TODO: Figure out if we want that for now
	config->support_include_db_version = false;
	config->support_pce_lsp_instantiation = false;
	config->support_lsp_triggered_resync = false;
	config->support_lsp_delta_sync = false;
	config->support_pce_triggered_initial_sync = false;

	sess = connect_pce_with_port(config, &pcc_state->opts->addr,
				     pcc_state->opts->port);

	if (NULL == sess) return 1;

	pcc_state->config = config;
	pcc_state->sess = sess;

	return 0;
}

void pcep_lib_disconnect(pcc_state_t *pcc_state)
{
	assert(NULL != pcc_state);
	assert(NULL != pcc_state->config);
	assert(NULL != pcc_state->sess);

	disconnect_pce(pcc_state->sess);

	free(pcc_state->config);
	pcc_state->config = NULL;
	pcc_state->sess = NULL;
}

double_linked_list *pcep_lib_format_path(path_t *path)
{
	struct in_addr addr_null;
	double_linked_list *objs, *srp_tlvs, *lsp_tlvs, *ero_objs;
	struct pcep_object_tlv *tlv;
	struct pcep_object_ro_subobj *ero_obj;
	struct pcep_object_srp* srp;
	struct pcep_object_lsp* lsp;
	struct pcep_object_ro* ero;

	memset(&addr_null, 0, sizeof(addr_null));

	objs = dll_initialize();

	/* SRP object */
	srp_tlvs = dll_initialize();
	tlv = pcep_tlv_create_path_setup_type(SR_TE_PST);
	dll_append(srp_tlvs, tlv);
	srp = pcep_obj_create_srp(path->do_remove, path->srp_id, srp_tlvs);
	dll_append(objs, srp);
	dll_destroy_with_data(srp_tlvs);
	/* LSP object */
	lsp_tlvs = dll_initialize();
	if (NULL != path->name) {
		tlv = pcep_tlv_create_symbolic_path_name(path->name,
							 strlen(path->name));
		dll_append(lsp_tlvs, tlv);
	}
	tlv = pcep_tlv_create_ipv4_lsp_identifiers(&addr_null, &addr_null, 0, 0, 0);
	dll_append(lsp_tlvs, tlv);
	lsp = pcep_obj_create_lsp(path->plsp_id,
				  path->status,
				  path->was_created   /* C Flag */,
				  path->go_active     /* A Flag */,
				  path->was_removed   /* R Flag */,
				  path->is_synching   /* S Flag */,
				  path->is_delegated  /* D Flag */,
				  lsp_tlvs);
	dll_append(objs, lsp);
	dll_destroy_with_data(lsp_tlvs);
	/*   ERO object */
	ero_objs = dll_initialize();
	for (path_hop_t *hop = path->first; NULL != hop; hop = hop->next) {
		/* Only supporting MPLS hops with both sid and nai */
		assert(hop->is_mpls);
		assert(hop->has_sid);
		assert(hop->has_nai);
		/* Only supporting IPv4 nodes */
		assert(PCEP_SR_SUBOBJ_NAI_IPV4_NODE == hop->type);

		ero_obj = pcep_obj_create_ro_subobj_sr_ipv4_node(
				hop->is_loose,
				!hop->has_sid,
				hop->has_attribs,
				hop->is_mpls,
				ENCODE_SR_ERO_SID(hop->sid.mpls.label,
						  hop->sid.mpls.traffic_class,
						  hop->sid.mpls.is_bottom,
						  hop->sid.mpls.ttl),
				&hop->nai.ipv4_node.local);
		/* ODL only supports Draft 07 that has a different type */
		ero_obj->subobj.sr.header.type = RO_SUBOBJ_TYPE_SR_DRAFT07;
		dll_append(ero_objs, ero_obj);
	}
	ero = pcep_obj_create_ero(ero_objs);
	dll_append(objs, ero);
	dll_destroy_with_data(ero_objs);

	return objs;
}

path_t *pcep_lib_parse_path(double_linked_list *objs)
{
	path_t *path;
	double_linked_list_node *node;

	struct pcep_object_header *obj;
	struct pcep_object_srp* srp = NULL;
	struct pcep_object_lsp* lsp = NULL;
	struct pcep_object_ro* ero = NULL;

	path = XCALLOC(MTYPE_PCEP, sizeof(*path));

	for (node = objs->head; node != NULL; node = node->next_node) {
		obj = (struct pcep_object_header *) node->data;
		switch (CLASS_TYPE(obj->object_class, obj->object_type)) {
			case CLASS_TYPE(PCEP_OBJ_CLASS_SRP, PCEP_OBJ_TYPE_SRP):
				assert(NULL == srp);
				srp = (struct pcep_object_srp*) obj;
				pcep_lib_parse_srp(path, srp);
				break;
			case CLASS_TYPE(PCEP_OBJ_CLASS_LSP, PCEP_OBJ_TYPE_LSP):
				/* Only support single LSP per message */
				assert(NULL == lsp);
				lsp = (struct pcep_object_lsp*) obj;
				pcep_lib_parse_lsp(path, lsp);
				break;
			case CLASS_TYPE(PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO):
				/* Only support single ERO per message */
				assert(NULL == ero);
				ero = (struct pcep_object_ro*) obj;
				pcep_lib_parse_ero(path, ero);
				break;
			default:
				PCEP_DEBUG("Unexpected PCEP object %s (%u) / %s (%u)",
					pcep_object_class_name(obj->object_class),
					obj->object_class,
					pcep_object_type_name(obj->object_class,
							      obj->object_type),
					obj->object_type);
				break;
	     }
	}

	return path;
}

void pcep_lib_parse_srp(path_t *path, struct pcep_object_srp* srp)
{
	double_linked_list *tlvs;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;

	path->do_remove = srp->lsp_remove;
	path->srp_id = srp->srp_id_number;

	tlvs = pcep_obj_get_tlvs(&srp->header);
	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *) node->data;
		switch (tlv->type) {
			case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
			default:
				PCEP_DEBUG("Unexpected SRP's TLV %s (%u)",
					pcep_tlv_type_name(tlv->type),
					tlv->type);
				break;

		}
	}

	dll_destroy(tlvs);
}

void pcep_lib_parse_lsp(path_t *path, struct pcep_object_lsp* lsp)
{
	double_linked_list *tlvs;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;

	tlvs = pcep_obj_get_tlvs(&lsp->header);
	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *) node->data;
		switch (tlv->type) {
			default:
				PCEP_DEBUG("Unexpected LSP TLV %s (%u)",
					pcep_tlv_type_name(tlv->type),
					tlv->type);
				break;

		}
	}

	dll_destroy(tlvs);
}

void pcep_lib_parse_ero(path_t *path, struct pcep_object_ro* ero)
{
	double_linked_list *objs;
	double_linked_list_node *node;
	struct pcep_ro_subobj_hdr *obj;

	objs = pcep_obj_get_ro_subobjects(&ero->header);
	for (node = objs->head; node != NULL; node = node->next_node) {
		obj = (struct pcep_ro_subobj_hdr *) node->data;
		switch (obj->type) {
			default:
				PCEP_DEBUG("Unexpected ERO sub-object %s (%u)",
					pcep_ro_type_name(obj->type),
					obj->type);
				break;

		}
	}

	dll_destroy(objs);
}

void pcep_lib_free_path(path_t *path)
{
	path_hop_t *hop;

	hop = path->first;
	while (NULL != hop) {
		path_hop_t *next = hop->next;
		XFREE(MTYPE_PCEP, hop);
		hop = next;
	}
	if (NULL != path->name) {
		XFREE(MTYPE_PCEP, path->name);
	}
	XFREE(MTYPE_PCEP, path);
}


/* ------------ PCC Functions ------------ */

pcc_state_t* pcep_pcc_initialize(ctrl_state_t *ctrl_state, int index)
{
	assert(NULL != ctrl_state);

	pcc_state_t *pcc_state = XCALLOC(MTYPE_PCEP, sizeof(*pcc_state));

	PCEP_DEBUG("PCC initializing...");

	pcc_state->index = index;
	pcc_state->status = DISCONNECTED;

	return pcc_state;
}

void pcep_pcc_finalize(ctrl_state_t *ctrl_state, pcc_state_t *pcc_state)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	PCEP_DEBUG("PCC finalizing...");

	pcep_pcc_disable(ctrl_state, pcc_state);

	if (NULL != pcc_state->opts) {
		XFREE(MTYPE_PCEP, pcc_state->opts);
		pcc_state->opts = NULL;
	}
	XFREE(MTYPE_PCEP, pcc_state);
}

int pcep_pcc_update(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state, pcc_opts_t *opts)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	int ret = 0;

	//TODO: check if the options changed ?

	if ((ret = pcep_pcc_disable(ctrl_state, pcc_state))) return ret;

	if (NULL != pcc_state->opts) {
		XFREE(MTYPE_PCEP, pcc_state->opts);
		pcc_state->opts = NULL;
	}

	pcc_state->opts = opts;

	return pcep_pcc_enable(ctrl_state, pcc_state);
}

int pcep_pcc_enable(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state)
{
	assert(DISCONNECTED == pcc_state->status);

	int ret = 0;

	PCEP_DEBUG("PCC connecting...");

	if ((ret = pcep_lib_connect(pcc_state))) {
		flog_err(EC_PATH_PCEP_LIB_CONNECT,
			 "failed to connect to PCE %pI4:%d (%d)",
			 &pcc_state->opts->addr, pcc_state->opts->port, ret);
		return ret;
	}

	pcc_state->status = CONNECTING;

	return ret;
}

int pcep_pcc_disable(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	switch (pcc_state->status) {
		case DISCONNECTED:
			return 0;
		case CONNECTING:
		case SYNCHRONIZING:
		case OPERATING:
			PCEP_DEBUG("Disconnecting PCC...");
			pcep_lib_disconnect(pcc_state);
			pcc_state->status = DISCONNECTED;
			return 0;
		default:
			return 1;
	}
}

void pcep_pcc_handle_pcep_event(ctrl_state_t *ctrl_state,
				pcc_state_t * pcc_state, pcep_event *event)
{
	PCEP_DEBUG("Received PCEP event: %s", format_pcep_event(event));
	switch (event->event_type) {
		case PCC_CONNECTED_TO_PCE:
			assert(CONNECTING == pcc_state->status);
			PCEP_DEBUG("Connection established to PCE %pI4:%i",
				   &pcc_state->opts->addr,
				   pcc_state->opts->port);
			pcep_pcc_synchronize(ctrl_state, pcc_state);
			break;
		case PCE_CLOSED_SOCKET:
		case PCE_SENT_PCEP_CLOSE:
		case PCE_DEAD_TIMER_EXPIRED:
		case PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED:
		case PCC_PCEP_SESSION_CLOSED:
		case PCC_RCVD_INVALID_OPEN:
		case PCC_RCVD_MAX_INVALID_MSGS:
		case PCC_RCVD_MAX_UNKOWN_MSGS:
			pcep_pcc_disable(ctrl_state, pcc_state);
			//TODO: schedule reconnection ??
			break;
		case MESSAGE_RECEIVED:
			if (CONNECTING == pcc_state->status) {
				assert(PCEP_TYPE_OPEN == event->message->header->type);
				break;
			}
			assert(SYNCHRONIZING == pcc_state->status
			       || OPERATING == pcc_state->status);
			pcep_pcc_handle_message(ctrl_state, pcc_state,
						event->message);
			break;
		default:
			//TODO: Log something ???
			break;
	}
}

void pcep_pcc_synchronize(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state)
{
	pcep_message *report;
	char name[10] = "foob";
	struct in_addr addr_r6;
	double_linked_list *objs;
	path_hop_t hop1;
	path_t path;

	pcc_state->status = SYNCHRONIZING;
	//TODO: Start synchronization, for now it is hard-coded

	inet_pton(AF_INET, "6.6.6.6", &(addr_r6.s_addr));

	/* First Fake Path */
	hop1 = (path_hop_t){
		.next = NULL,
		.type = PCEP_SR_SUBOBJ_NAI_IPV4_NODE,
		.is_loose = false,
		.has_sid = true,
		.has_attribs = false,
		.is_mpls = true,
		.has_nai = true,
		.sid = {
			.mpls = {
				.label = 16060,
				.traffic_class = 0,
				.is_bottom = true,
				.ttl = 0
			}
		},
		.nai = { .ipv4_node = { .local = addr_r6 } }
	};
	path = (path_t){
		.name = name,
		.srp_id = 0,
		.plsp_id = 42,
		.status = PCEP_LSP_OPERATIONAL_UP,
		.do_remove = false,
		.go_active = false,
		.was_created = false,
		.was_removed = false,
		.is_synching = true,
		.is_delegated = true,
		.first = &hop1
	};
	objs = pcep_lib_format_path(&path);
	report = pcep_msg_create_report(objs);
	pcep_pcc_send(ctrl_state, pcc_state, report);
	dll_destroy_with_data(objs);

	/* End Synchronization */
	path = (path_t){
		.name = NULL,
		.srp_id = 0,
		.plsp_id = 0,
		.status = PCEP_LSP_OPERATIONAL_DOWN,
		.do_remove = false,
		.go_active = false,
		.was_created = false,
		.was_removed = false,
		.is_synching = false,
		.is_delegated = false,
		.first = NULL
	};
	objs = pcep_lib_format_path(&path);
	report = pcep_msg_create_report(objs);
	pcep_pcc_send(ctrl_state, pcc_state, report);
	dll_destroy_with_data(objs);

	pcc_state->status = OPERATING;
}

void pcep_pcc_handle_message(ctrl_state_t *ctrl_state,
			     pcc_state_t * pcc_state, pcep_message *msg)
{
	switch (msg->header->type) {
		case PCEP_TYPE_INITIATE:
			pcep_pcc_lsp_initiate(ctrl_state, pcc_state, msg);
			break;
		case PCEP_TYPE_UPDATE:
			pcep_pcc_lsp_update(ctrl_state, pcc_state, msg);
			break;
		default:
			break;
	}
}

void pcep_pcc_lsp_update(ctrl_state_t *ctrl_state,
			 pcc_state_t * pcc_state, pcep_message *msg)
{
	path_t *path;

	path = pcep_lib_parse_path(msg->obj_list);

	pcep_lib_free_path(path);
}

void pcep_pcc_lsp_initiate(ctrl_state_t *ctrl_state,
			   pcc_state_t * pcc_state, pcep_message *msg)
{
	PCEP_DEBUG("Received LSP initiate, not supported yet");
}

void pcep_pcc_send(ctrl_state_t *ctrl_state,
		   pcc_state_t * pcc_state, pcep_message *msg)
{
	// PCEP_DEBUG("Sending PCEP message: %s", format_pcep_message(msg));
	send_message(pcc_state->sess, msg, true);
}


/* ------------ Controller Functions Called from Main ------------ */

int pcep_controller_initialize(void)
{
	int ret;
	ctrl_state_t *ctrl_state;
	struct frr_pthread *fpt;
	struct frr_pthread_attr attr = {
		.start = frr_pthread_attr_default.start,
		.stop = pcep_halt_cb,
	};

	assert(NULL == pcep_g->fpt);
	assert(!pcep_g->fpt);

	if (!initialize_pcc()) {
		flog_err(EC_PATH_PCEP_PCC_INIT,
			 "failed to initialize PCC");
		return 1;
	}

	/* Create and start the FRR pthread */
	fpt = frr_pthread_new(&attr, "PCEP thread", "pcep");
	if (NULL == fpt) {
		flog_err(EC_PATH_SYSTEM_CALL,
			 "failed to initialize PCEP thread");
		return 1;
	}
	ret = frr_pthread_run(fpt, NULL);
	if (ret < 0) {
		flog_err(EC_PATH_SYSTEM_CALL,
			 "failed to create PCEP thread");
		return ret;
	}
	frr_pthread_wait_running(fpt);

	/* Initialise the thread state */
	ctrl_state = XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state));
	ctrl_state->main = pcep_g->master;
	ctrl_state->self = fpt->master;
	ctrl_state->t_poll = NULL;
	ctrl_state->pcc_count = 0;

	/* Keep the state reference for events */
	fpt->data = ctrl_state;
	pcep_g->fpt = fpt;

	/* Initialize the PCEP thread */
	thread_add_event(ctrl_state->self,
			 pcep_thread_init_event,
			 (void*)ctrl_state, 0, NULL);

	return 0;
}

int pcep_controller_finalize(void)
{
	int ret = 0;

	if (NULL != pcep_g->fpt) {
		frr_pthread_stop(pcep_g->fpt, NULL);
		pcep_g->fpt = NULL;

		if (!destroy_pcc())
		{
			flog_err(EC_PATH_PCEP_PCC_FINI,
				 "failed to finalize PCC");
		}
	}

	return ret;
}

int pcep_controller_pcc_update(int index, pcc_opts_t *opts)
{
	ctrl_state_t *ctrl_state;
	event_pcc_update_t *event;

	assert(NULL != opts);
	assert(index < MAX_PCC);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (ctrl_state_t*)pcep_g->fpt->data;
	assert(index <= ctrl_state->pcc_count);

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->pcc_opts = opts;
	event->pcc_index = index;
	thread_add_event(ctrl_state->self,
			 pcep_thread_pcc_update_event,
			 (void*)event, 0, NULL);

	return 0;
}

int pcep_controller_pcc_disconnect(int index)
{
	ctrl_state_t *ctrl_state;

	assert(index < MAX_PCC);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (ctrl_state_t*)pcep_g->fpt->data;
	assert(index < ctrl_state->pcc_count);

	thread_add_event(ctrl_state->self,
			 pcep_thread_pcc_disconnect_event,
			 (void*)ctrl_state, index, NULL);

	return 0;
}

int pcep_halt_cb(struct frr_pthread *fpt, void **res)
{
	thread_add_event(fpt->master,
			 pcep_thread_finish_event, (void*)fpt, 0, NULL);
	pthread_join(fpt->thread, res);

	return 0;
}


/* ------------ Controller Functions Called From Thread ------------ */

#if 0
/* Notifies the main thread that it should start sending LSP to synchronize
   the PCC */
void pcep_thread_start_sync(ctrl_state_t *ctrl_state)
{
	assert(NULL != ctrl_state);

	thread_add_event(ctrl_state->main,
			 pcep_main_start_sync_event,
			 NULL, 0, NULL);
}

void pcep_thread_update_lsp(ctrl_state_t *ctrl_state)
{
	assert(NULL != ctrl_state);

	thread_add_event(ctrl_state->main,
			 pcep_main_update_lsp_event,
			 NULL, 0, NULL);
}
#endif

void pcep_thread_schedule_poll(ctrl_state_t *ctrl_state)
{
	assert(NULL == ctrl_state->t_poll);
	thread_add_timer(ctrl_state->self, pcep_thread_poll_timer,
			 (void*)ctrl_state, POLL_INTERVAL,
			 &ctrl_state->t_poll);
}

int pcep_thread_init_event(struct thread *thread)
{
	ctrl_state_t *ctrl_state = THREAD_ARG(thread);
	int ret = 0;

	pcep_thread_schedule_poll(ctrl_state);

	return ret;
}

int pcep_thread_finish_event(struct thread *thread)
{
	int i;
	struct frr_pthread *fpt = THREAD_ARG(thread);
	ctrl_state_t *ctrl_state = fpt->data;

	assert(NULL != ctrl_state);

	if (NULL != ctrl_state->t_poll) {
		thread_cancel(ctrl_state->t_poll);
	}

	for (i = 0; i < ctrl_state->pcc_count; i++) {
		pcep_pcc_finalize(ctrl_state, ctrl_state->pcc[i]);
		ctrl_state->pcc[i] = NULL;
	}

	XFREE(MTYPE_PCEP, ctrl_state);
	fpt->data = NULL;

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
	return 0;
}

int pcep_thread_poll_timer(struct thread *thread)
{
	int i;
	ctrl_state_t *ctrl_state = THREAD_ARG(thread);
	pcep_event *event;

	assert(NULL != ctrl_state);
	assert(NULL == ctrl_state->t_poll);

	while (NULL != (event = event_queue_get_event())) {
		for (i = 0; i < ctrl_state->pcc_count; i++) {
			pcc_state_t *pcc_state = ctrl_state->pcc[i];
			if (pcc_state->sess != event->session) continue;
			pcep_pcc_handle_pcep_event(ctrl_state, pcc_state, event);
			break;
		}
		destroy_pcep_event(event);
	}

	pcep_thread_schedule_poll(ctrl_state);

	return 0;
}

int pcep_thread_pcc_update_event(struct thread *thread)
{
	event_pcc_update_t *event = THREAD_ARG(thread);
	ctrl_state_t *ctrl_state = event->ctrl_state;
	int pcc_index = event->pcc_index;
	pcc_opts_t *pcc_opts = event->pcc_opts;
	pcc_state_t *pcc_state;
	int ret = 0;

	XFREE(MTYPE_PCEP, event);

	if (pcc_index == ctrl_state->pcc_count) {
		pcc_state = pcep_pcc_initialize(ctrl_state, pcc_index);
		ctrl_state->pcc_count = pcc_index + 1;
		ctrl_state->pcc[pcc_index] = pcc_state;
	} else {
		pcc_state = ctrl_state->pcc[pcc_index];
	}

	if (pcep_pcc_update(ctrl_state, pcc_state, pcc_opts)) {
		flog_err(EC_PATH_PCEP_PCC_CONF_UPDATE,
			 "failed to update PCC configuration");
	}

	return ret;
}

int pcep_thread_pcc_disconnect_event(struct thread *thread)
{
	ctrl_state_t *ctrl_state = THREAD_ARG(thread);
	pcc_state_t *pcc_state;
	int pcc_index = THREAD_VAL(thread);
	int ret = 0;

	if (pcc_index < ctrl_state->pcc_count) {
		pcc_state = ctrl_state->pcc[pcc_index];
		pcep_pcc_disable(ctrl_state, pcc_state);
	}

	return ret;
}


/* ------------ Main Thread Functions ------------ */

#if 0
int pcep_main_start_sync_event(struct thread *thread)
{
	return 0;
}

int pcep_main_update_lsp_event(struct thread *thread)
{
	return 0;
}
#endif


/* ------------ CLI Functions ------------ */

DEFUN (pcep_cli_pce_ip,
       pcep_cli_pce_ip_cmd,
	"pce ip A.B.C.D [port (1024-65535)]",
	"PCE remote ip and port\n"
	"Remote PCE server ip A.B.C.D\n"
	"Remote PCE server port")
{
	struct in_addr pce_addr;
	uint32_t pce_port = PCEP_DEFAULT_PORT;
	pcc_opts_t *opts;

	int ip_idx = 2;
	int port_idx = 4;

	if (!inet_pton(AF_INET, argv[ip_idx]->arg, &(pce_addr.s_addr)))
		return CMD_ERR_INCOMPLETE;

	if (argc > port_idx)
		pce_port = atoi(argv[port_idx]->arg);

	opts = XCALLOC(MTYPE_PCEP, sizeof(*opts));
	opts->addr = pce_addr;
	opts->port = pce_port;

	if (pcep_controller_pcc_update(0, opts))
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN (pcep_cli_no_pce,
       pcep_cli_no_pce_cmd,
	"no pce",
	NO_STR
	"Disable pce\n")
{
	pcep_controller_pcc_disconnect(0);
	return CMD_SUCCESS;
}

DEFUN (pcep_cli_debug,
       pcep_cli_debug_cmd,
       "[no] debug pathd pcep",
       NO_STR
       DEBUG_STR
       "Pathd debugging\n"
       "pcep\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, "no");

	DEBUG_MODE_SET(&pcep_g->dbg, mode, !no);

	return CMD_SUCCESS;
}

int pcep_cli_debug_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_CONF))
		vty_out(vty, "debug pathd pcep\n");

	return 0;
}

int pcep_cli_debug_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&pcep_g->dbg, flags, set);

	/* If all modes have been turned off, don't preserve options. */
	if (!DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_ALL))
		DEBUG_CLEAR(&pcep_g->dbg);

	return 0;
}

void pcep_cli_init(void)
{
	hook_register(nb_client_debug_config_write,
		      pcep_cli_debug_config_write);
	hook_register(nb_client_debug_set_all,
		      pcep_cli_debug_set_all);

	install_element(ENABLE_NODE, &pcep_cli_debug_cmd);
	install_element(CONFIG_NODE, &pcep_cli_debug_cmd);
	install_element(CONFIG_NODE, &pcep_cli_pce_ip_cmd);
	install_element(CONFIG_NODE, &pcep_cli_no_pce_cmd);

}

/* ------------ Module Functions ------------ */

int pcep_module_late_init(struct thread_master *tm)
{
	pcep_g->master = tm;

	if (pcep_controller_initialize()) return 1;

	hook_register(frr_fini, pcep_module_finish);
	pcep_cli_init();

	return 0;
}

int pcep_module_finish(void)
{
	pcep_controller_finalize();

	return 0;
}

int pcep_module_init(void)
{
	hook_register(frr_late_init, pcep_module_late_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "frr_pathd_pcep", .version = FRR_VERSION,
		 .description = "FRR pathd PCEP module",
		 .init = pcep_module_init)
