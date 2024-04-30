/*
 * Copyright (C) 2020  NetDEF, Inc.
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

#include "memory.h"

#include <debug.h>
#include "pceplib/pcep_utils_counters.h"
#include "pceplib/pcep_timers.h"
#include "pathd/path_errors.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_debug.h"

DEFINE_MTYPE_STATIC(PATHD, PCEPLIB_INFRA,    "PCEPlib Infrastructure");
DEFINE_MTYPE_STATIC(PATHD, PCEPLIB_MESSAGES, "PCEPlib PCEP Messages");

#define CLASS_TYPE(CLASS, TYPE) (((CLASS) << 16) | (TYPE))
#define DEFAULT_LSAP_SETUP_PRIO 4
#define DEFAULT_LSAP_HOLDING_PRIO 4
#define DEFAULT_LSAP_LOCAL_PRETECTION false
#define MAX_PATH_NAME_SIZE 255

/* pceplib logging callback */
static int pceplib_logging_cb(int level, const char *fmt, va_list args)
	PRINTFRR(2, 0);

/* Socket callbacks */
static int pcep_lib_pceplib_socket_read_cb(void *fpt, void **thread, int fd,
					   void *payload);
static int pcep_lib_pceplib_socket_write_cb(void *fpt, void **thread, int fd,
					    void *payload);
static void pcep_lib_socket_read_ready(struct thread *thread);
static void pcep_lib_socket_write_ready(struct thread *thread);

/* pceplib pcep_event callbacks */
static void pcep_lib_pceplib_event_cb(void *fpt, pcep_event *event);

/* pceplib pthread creation callback */
static int pcep_lib_pthread_create_cb(pthread_t *pthread_id,
				      const pthread_attr_t *attr,
				      void *(*start_routine)(void *),
				      void *data, const char *thread_name);
void *pcep_lib_pthread_start_passthrough(void *data);
int pcep_lib_pthread_stop_cb(struct frr_pthread *, void **);

/* Internal functions */
static double_linked_list *pcep_lib_format_path(struct pcep_caps *caps,
						struct path *path);
static void pcep_lib_format_constraints(struct path *path,
					double_linked_list *objs);
static void pcep_lib_parse_open(struct pcep_caps *caps,
				struct pcep_object_open *open);
static void
pcep_lib_parse_open_pce_capability(struct pcep_caps *caps,
				   struct pcep_object_tlv_header *tlv_header);
static void
pcep_lib_parse_open_objfun_list(struct pcep_caps *caps,
				struct pcep_object_tlv_header *tlv_header);
static void pcep_lib_parse_rp(struct path *path, struct pcep_object_rp *rp);
static void pcep_lib_parse_srp(struct path *path, struct pcep_object_srp *srp);
static void pcep_lib_parse_lsp(struct path *path, struct pcep_object_lsp *lsp);
static void pcep_lib_parse_lspa(struct path *path,
				struct pcep_object_lspa *lspa);
static void pcep_lib_parse_lsp_symbolic_name(
	struct path *path, struct pcep_object_tlv_symbolic_path_name *tlv);
static void pcep_lib_parse_metric(struct path *path,
				  struct pcep_object_metric *obj);
static void
pcep_lib_parse_endpoints_ipv4(struct path *path,
			      struct pcep_object_endpoints_ipv4 *obj);
static void
pcep_lib_parse_endpoints_ipv6(struct path *path,
			      struct pcep_object_endpoints_ipv6 *obj);
static void pcep_lib_parse_vendor_info(struct path *path,
				       struct pcep_object_vendor_info *obj);
static void pcep_lib_parse_ero(struct path *path, struct pcep_object_ro *ero);
static struct path_hop *pcep_lib_parse_ero_sr(struct path_hop *next,
					      struct pcep_ro_subobj_sr *sr);
static struct counters_group *copy_counter_group(struct counters_group *from);
static struct counters_subgroup *
copy_counter_subgroup(struct counters_subgroup *from);
static struct counter *copy_counter(struct counter *from);
static void free_counter_group(struct counters_group *group);
static void free_counter_subgroup(struct counters_subgroup *subgroup);
static void free_counter(struct counter *counter);

struct pcep_lib_pthread_passthrough_data {
	void *(*start_routine)(void *data);
	void *data;
};

/* ------------ API Functions ------------ */

int pcep_lib_initialize(struct frr_pthread *fpt)
{
	PCEP_DEBUG("Initializing pceplib");

	/* Register pceplib logging callback */
	register_logger(pceplib_logging_cb);

	/* Its ok that this object goes out of scope, as it
	 * wont be stored, and its values will be copied */
	struct pceplib_infra_config infra = {
		/* Memory infrastructure */
		.pceplib_infra_mt = MTYPE_PCEPLIB_INFRA,
		.pceplib_messages_mt = MTYPE_PCEPLIB_MESSAGES,
		.malloc_func = (pceplib_malloc_func)qmalloc,
		.calloc_func = (pceplib_calloc_func)qcalloc,
		.realloc_func = (pceplib_realloc_func)qrealloc,
		.strdup_func = (pceplib_strdup_func)qstrdup,
		.free_func = (pceplib_free_func)qfree,
		/* Timers infrastructure */
		.external_infra_data = fpt,
		.socket_read_func = pcep_lib_pceplib_socket_read_cb,
		.socket_write_func = pcep_lib_pceplib_socket_write_cb,
		/* PCEP events */
		.pcep_event_func = pcep_lib_pceplib_event_cb,
		/* PCEPlib pthread creation callback */
		.pthread_create_func = pcep_lib_pthread_create_cb};
	if (!initialize_pcc_infra(&infra)) {
		flog_err(EC_PATH_PCEP_PCC_INIT, "failed to initialize pceplib");
		return 1;
	}

	return 0;
}

void pcep_lib_finalize(void)
{
	PCEP_DEBUG("Finalizing pceplib");
	if (!destroy_pcc()) {
		flog_err(EC_PATH_PCEP_PCC_FINI, "failed to finalize pceplib");
	}
}


pcep_session *
pcep_lib_connect(struct ipaddr *src_addr, int src_port, struct ipaddr *dst_addr,
		 int dst_port, short msd,
		 const struct pcep_config_group_opts *pcep_options)
{
	pcep_configuration *config;
	pcep_session *sess;

	config = create_default_pcep_configuration();
	config->dst_pcep_port = dst_port;
	config->src_pcep_port = src_port;
	if (IS_IPADDR_V6(src_addr)) {
		config->is_src_ipv6 = true;
		memcpy(&config->src_ip.src_ipv6, &src_addr->ipaddr_v6,
		       sizeof(struct in6_addr));
	} else {
		config->is_src_ipv6 = false;
		config->src_ip.src_ipv4 = src_addr->ipaddr_v4;
	}

	config->support_stateful_pce_lsp_update = true;
	config->support_pce_lsp_instantiation = pcep_options->pce_initiated;
	config->support_include_db_version = false;
	config->support_lsp_triggered_resync = false;
	config->support_lsp_delta_sync = false;
	config->support_pce_triggered_initial_sync = false;
	config->support_sr_te_pst = true;
	config->pcc_can_resolve_nai_to_sid = false;

	config->max_sid_depth = msd;
	config->pcep_msg_versioning->draft_ietf_pce_segment_routing_07 =
		pcep_options->draft07;
	config->keep_alive_seconds = pcep_options->keep_alive_seconds;
	config->min_keep_alive_seconds = pcep_options->min_keep_alive_seconds;
	config->max_keep_alive_seconds = pcep_options->max_keep_alive_seconds;
	config->dead_timer_seconds = pcep_options->dead_timer_seconds;
	config->min_dead_timer_seconds = pcep_options->min_dead_timer_seconds;
	config->max_dead_timer_seconds = pcep_options->max_dead_timer_seconds;
	config->request_time_seconds = pcep_options->pcep_request_time_seconds;
	/* TODO when available in the pceplib, set it here
	 pcep_options->state_timeout_inteval_seconds;*/

	if (pcep_options->tcp_md5_auth[0] != '\0') {
		config->is_tcp_auth_md5 = true;
		strlcpy(config->tcp_authentication_str,
			pcep_options->tcp_md5_auth,
			sizeof(config->tcp_authentication_str));
	} else {
		config->is_tcp_auth_md5 = false;
	}

	if (IS_IPADDR_V6(dst_addr)) {
		sess = connect_pce_ipv6(config, &dst_addr->ipaddr_v6);
	} else {
		sess = connect_pce(config, &dst_addr->ipaddr_v4);
	}
	destroy_pcep_configuration(config);
	return sess;
}

void pcep_lib_disconnect(pcep_session *sess)
{
	assert(sess != NULL);
	disconnect_pce(sess);
}

/* Callback passed to pceplib to write to a socket.
 * When the socket is ready to be written to,
 * pcep_lib_socket_write_ready() will be called */

int pcep_lib_pceplib_socket_write_cb(void *fpt, void **thread, int fd,
				     void *payload)
{
	return pcep_thread_socket_write(fpt, thread, fd, payload,
					pcep_lib_socket_write_ready);
}

/* Callback passed to pceplib to read from a socket.
 * When the socket is ready to be read from,
 * pcep_lib_socket_read_ready() will be called */

int pcep_lib_pceplib_socket_read_cb(void *fpt, void **thread, int fd,
				    void *payload)
{
	return pcep_thread_socket_read(fpt, thread, fd, payload,
				       pcep_lib_socket_read_ready);
}

/* Callbacks called by path_pcep_controller when a socket is ready to read/write
 */

void pcep_lib_socket_write_ready(struct thread *thread)
{
	struct pcep_ctrl_socket_data *data = THREAD_ARG(thread);
	assert(data != NULL);

	pceplib_external_socket_write(data->fd, data->payload);
	XFREE(MTYPE_PCEP, data);
}

void pcep_lib_socket_read_ready(struct thread *thread)
{
	struct pcep_ctrl_socket_data *data = THREAD_ARG(thread);
	assert(data != NULL);

	pceplib_external_socket_read(data->fd, data->payload);
	XFREE(MTYPE_PCEP, data);
}

/* Callback passed to pceplib when a pcep_event is ready */
void pcep_lib_pceplib_event_cb(void *fpt, pcep_event *event)
{
	pcep_thread_send_ctrl_event(fpt, event, pcep_thread_pcep_event);
}

/* Wrapper function around the actual pceplib thread start function */
void *pcep_lib_pthread_start_passthrough(void *data)
{
	struct frr_pthread *fpt = data;
	struct pcep_lib_pthread_passthrough_data *passthrough_data = fpt->data;
	void *start_routine_data = passthrough_data->data;
	void *(*start_routine)(void *) = passthrough_data->start_routine;
	XFREE(MTYPE_PCEP, passthrough_data);

	if (start_routine != NULL) {
		return start_routine(start_routine_data);
	}

	return NULL;
}

int pcep_lib_pthread_create_cb(pthread_t *thread_id, const pthread_attr_t *attr,
			       void *(*start_routine)(void *), void *data,
			       const char *thread_name)
{
	/* Since FRR calls the start_routine with a struct frr_pthread,
	 * we have to store the real data and callback in a passthrough
	 * and pass the actual data the start_routine needs */
	struct pcep_lib_pthread_passthrough_data *passthrough_data = XMALLOC(
		MTYPE_PCEP, sizeof(struct pcep_lib_pthread_passthrough_data));
	passthrough_data->data = data;
	passthrough_data->start_routine = start_routine;

	struct frr_pthread_attr fpt_attr = {
		.start = pcep_lib_pthread_start_passthrough,
		.stop = pcep_lib_pthread_stop_cb};
	struct frr_pthread *fpt =
		frr_pthread_new(&fpt_attr, thread_name, "pcep_lib");
	if (fpt == NULL) {
		return 1;
	}

	fpt->data = passthrough_data;
	int retval = frr_pthread_run(fpt, attr);
	if (retval) {
		return retval;
	}

	*thread_id = fpt->thread;

	return 0;
}

int pcep_lib_pthread_stop_cb(struct frr_pthread *fpt, void **res)
{
	pcep_lib_finalize();
	frr_pthread_destroy(fpt);

	return 0;
}

struct pcep_message *pcep_lib_format_report(struct pcep_caps *caps,
					    struct path *path)
{
	double_linked_list *objs = pcep_lib_format_path(caps, path);
	return pcep_msg_create_report(objs);
}

static struct pcep_object_rp *create_rp(uint32_t reqid)
{
	double_linked_list *rp_tlvs;
	struct pcep_object_tlv_path_setup_type *setup_type_tlv;
	struct pcep_object_rp *rp;

	rp_tlvs = dll_initialize();
	setup_type_tlv = pcep_tlv_create_path_setup_type(SR_TE_PST);
	dll_append(rp_tlvs, setup_type_tlv);

	rp = pcep_obj_create_rp(0, false, false, false, true, reqid, rp_tlvs);

	return rp;
}

struct pcep_message *pcep_lib_format_request(struct pcep_caps *caps,
					     struct path *path)
{
	struct ipaddr *src = &path->pcc_addr;
	struct ipaddr *dst = &path->nbkey.endpoint;
	double_linked_list *objs;
	struct pcep_object_rp *rp;
	struct pcep_object_endpoints_ipv4 *endpoints_ipv4;
	struct pcep_object_endpoints_ipv6 *endpoints_ipv6;
	struct pcep_object_objective_function *of = NULL;
	enum objfun_type objfun = OBJFUN_UNDEFINED;

	assert(src->ipa_type == dst->ipa_type);

	objs = dll_initialize();
	rp = create_rp(path->req_id);
	rp->header.flag_p = true;

	pcep_lib_format_constraints(path, objs);

	/* Objective Function */
	if (path->has_pcc_objfun) {
		objfun = path->pcc_objfun;
	}

	if (objfun != OBJFUN_UNDEFINED) {
		of = pcep_obj_create_objective_function(objfun, NULL);
		assert(of != NULL);
		of->header.flag_p = path->enforce_pcc_objfun;
		dll_append(objs, of);
	}

	if (IS_IPADDR_V6(src)) {
		endpoints_ipv6 = pcep_obj_create_endpoint_ipv6(&src->ipaddr_v6,
							       &dst->ipaddr_v6);
		endpoints_ipv6->header.flag_p = true;
		return pcep_msg_create_request_ipv6(rp, endpoints_ipv6, objs);
	} else {
		endpoints_ipv4 = pcep_obj_create_endpoint_ipv4(&src->ipaddr_v4,
							       &dst->ipaddr_v4);
		endpoints_ipv4->header.flag_p = true;
		return pcep_msg_create_request(rp, endpoints_ipv4, objs);
	}
}

struct pcep_message *pcep_lib_format_error(int error_type, int error_value,
					   struct path *path)
{
	double_linked_list *objs, *srp_tlvs;
	struct pcep_object_srp *srp;
	struct pcep_object_tlv_header *tlv;

	if ((path == NULL) || (path->srp_id == 0))
		return pcep_msg_create_error(error_type, error_value);

	objs = dll_initialize();
	srp_tlvs = dll_initialize();
	tlv = (struct pcep_object_tlv_header *)pcep_tlv_create_path_setup_type(
		SR_TE_PST);
	dll_append(srp_tlvs, tlv);
	srp = pcep_obj_create_srp(path->do_remove, path->srp_id, srp_tlvs);
	dll_append(objs, srp);
	return pcep_msg_create_error_with_objects(error_type, error_value,
						  objs);
}

struct pcep_message *pcep_lib_format_request_cancelled(uint32_t reqid)
{
	struct pcep_object_notify *notify;
	double_linked_list *objs;
	struct pcep_object_rp *rp;

	notify = pcep_obj_create_notify(
		PCEP_NOTIFY_TYPE_PENDING_REQUEST_CANCELLED,
		PCEP_NOTIFY_VALUE_PCC_CANCELLED_REQUEST);
	objs = dll_initialize();
	rp = create_rp(reqid);
	dll_append(objs, rp);

	return pcep_msg_create_notify(notify, objs);
}

struct path *pcep_lib_parse_path(struct pcep_message *msg)
{
	struct path *path;
	double_linked_list *objs = msg->obj_list;
	double_linked_list_node *node;

	struct pcep_object_header *obj;
	struct pcep_object_rp *rp = NULL;
	struct pcep_object_srp *srp = NULL;
	struct pcep_object_lsp *lsp = NULL;
	struct pcep_object_lspa *lspa = NULL;
	struct pcep_object_ro *ero = NULL;
	struct pcep_object_metric *metric = NULL;
	struct pcep_object_bandwidth *bandwidth = NULL;
	struct pcep_object_objective_function *of = NULL;
	struct pcep_object_endpoints_ipv4 *epv4 = NULL;
	struct pcep_object_endpoints_ipv6 *epv6 = NULL;
	struct pcep_object_vendor_info *vendor_info = NULL;

	path = pcep_new_path();

	for (node = objs->head; node != NULL; node = node->next_node) {
		obj = (struct pcep_object_header *)node->data;
		switch (CLASS_TYPE(obj->object_class, obj->object_type)) {
		case CLASS_TYPE(PCEP_OBJ_CLASS_RP, PCEP_OBJ_TYPE_RP):
			assert(rp == NULL);
			rp = (struct pcep_object_rp *)obj;
			pcep_lib_parse_rp(path, rp);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_SRP, PCEP_OBJ_TYPE_SRP):
			assert(srp == NULL);
			srp = (struct pcep_object_srp *)obj;
			pcep_lib_parse_srp(path, srp);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_LSP, PCEP_OBJ_TYPE_LSP):
			/* Only support single LSP per message */
			assert(lsp == NULL);
			lsp = (struct pcep_object_lsp *)obj;
			pcep_lib_parse_lsp(path, lsp);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_LSPA, PCEP_OBJ_TYPE_LSPA):
			assert(lspa == NULL);
			lspa = (struct pcep_object_lspa *)obj;
			pcep_lib_parse_lspa(path, lspa);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO):
			/* Only support single ERO per message */
			assert(ero == NULL);
			ero = (struct pcep_object_ro *)obj;
			pcep_lib_parse_ero(path, ero);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_METRIC, PCEP_OBJ_TYPE_METRIC):
			metric = (struct pcep_object_metric *)obj;
			pcep_lib_parse_metric(path, metric);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_BANDWIDTH,
				PCEP_OBJ_TYPE_BANDWIDTH_REQ):
		case CLASS_TYPE(PCEP_OBJ_CLASS_BANDWIDTH,
				PCEP_OBJ_TYPE_BANDWIDTH_CISCO):
			bandwidth = (struct pcep_object_bandwidth *)obj;
			path->has_bandwidth = true;
			path->bandwidth = bandwidth->bandwidth;
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_NOPATH, PCEP_OBJ_TYPE_NOPATH):
			path->no_path = true;
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_OF, PCEP_OBJ_TYPE_OF):
			of = (struct pcep_object_objective_function *)obj;
			path->has_pce_objfun = true;
			path->pce_objfun = of->of_code;
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_ENDPOINTS,
				PCEP_OBJ_TYPE_ENDPOINT_IPV4):
			epv4 = (struct pcep_object_endpoints_ipv4 *)obj;
			pcep_lib_parse_endpoints_ipv4(path, epv4);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_ENDPOINTS,
				PCEP_OBJ_TYPE_ENDPOINT_IPV6):
			epv6 = (struct pcep_object_endpoints_ipv6 *)obj;
			pcep_lib_parse_endpoints_ipv6(path, epv6);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_VENDOR_INFO,
				PCEP_OBJ_TYPE_VENDOR_INFO):
			vendor_info = (struct pcep_object_vendor_info *)obj;
			pcep_lib_parse_vendor_info(path, vendor_info);
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_OBJECT,
				  "Unexpected PCEP object %s (%u) / %s (%u)",
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

void pcep_lib_parse_capabilities(struct pcep_message *msg,
				 struct pcep_caps *caps)
{
	double_linked_list *objs = msg->obj_list;
	double_linked_list_node *node;

	struct pcep_object_header *obj;
	struct pcep_object_open *open = NULL;

	for (node = objs->head; node != NULL; node = node->next_node) {
		obj = (struct pcep_object_header *)node->data;
		switch (CLASS_TYPE(obj->object_class, obj->object_type)) {
		case CLASS_TYPE(PCEP_OBJ_CLASS_OPEN, PCEP_OBJ_TYPE_OPEN):
			assert(open == NULL);
			open = (struct pcep_object_open *)obj;
			pcep_lib_parse_open(caps, open);
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_OBJECT,
				  "Unexpected PCEP object %s (%u) / %s (%u)",
				  pcep_object_class_name(obj->object_class),
				  obj->object_class,
				  pcep_object_type_name(obj->object_class,
							obj->object_type),
				  obj->object_type);
			break;
		}
	}
}

struct counters_group *pcep_lib_copy_counters(pcep_session *sess)
{
	if (!sess || !sess->pcep_session_counters) {
		return NULL;
	}

	return copy_counter_group(sess->pcep_session_counters);
}

void pcep_lib_free_counters(struct counters_group *counters)
{
	free_counter_group(counters);
}

pcep_session *pcep_lib_copy_pcep_session(pcep_session *sess)
{
	if (!sess) {
		return NULL;
	}

	pcep_session *copy;
	copy = XCALLOC(MTYPE_PCEP, sizeof(*copy));
	memcpy(copy, sess, sizeof(*copy));
	/* These fields should not be accessed */
	copy->num_unknown_messages_time_queue = NULL;
	copy->socket_comm_session = NULL;
	copy->pcep_session_counters = NULL;

	return copy;
}

/* ------------ pceplib logging callback ------------ */

int pceplib_logging_cb(int priority, const char *fmt, va_list args)
{
	char buffer[1024];
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	PCEP_DEBUG_PCEPLIB(priority, "pceplib: %s", buffer);
	return 0;
}

/* ------------ Internal Functions ------------ */

double_linked_list *pcep_lib_format_path(struct pcep_caps *caps,
					 struct path *path)
{
	struct in_addr addr_null;
	double_linked_list *objs, *srp_tlvs, *lsp_tlvs, *ero_objs;
	struct pcep_object_tlv_header *tlv;
	struct pcep_object_ro_subobj *ero_obj;
	struct pcep_object_srp *srp;
	struct pcep_object_lsp *lsp;
	struct pcep_object_ro *ero;
	uint32_t encoded_binding_sid;
	char binding_sid_lsp_tlv_data[6];

	memset(&addr_null, 0, sizeof(addr_null));

	objs = dll_initialize();

	if (path->plsp_id != 0) {
		/* SRP object */
		srp_tlvs = dll_initialize();
		tlv = (struct pcep_object_tlv_header *)
			pcep_tlv_create_path_setup_type(SR_TE_PST);
		assert(tlv != NULL);
		dll_append(srp_tlvs, tlv);
		srp = pcep_obj_create_srp(path->do_remove, path->srp_id,
					  srp_tlvs);
		assert(srp != NULL);
		srp->header.flag_p = true;
		dll_append(objs, srp);
	}

	/* LSP object */
	lsp_tlvs = dll_initialize();

	if (path->plsp_id == 0 || IS_IPADDR_NONE(&path->nbkey.endpoint)
	    || IS_IPADDR_NONE(&path->pcc_addr)) {
		tlv = (struct pcep_object_tlv_header *)
			pcep_tlv_create_ipv4_lsp_identifiers(
				&addr_null, &addr_null, 0, 0, &addr_null);
	} else {
		assert(path->pcc_addr.ipa_type
		       == path->nbkey.endpoint.ipa_type);
		if (IS_IPADDR_V4(&path->pcc_addr)) {
			tlv = (struct pcep_object_tlv_header *)
				pcep_tlv_create_ipv4_lsp_identifiers(
					&path->pcc_addr.ipaddr_v4,
					&path->nbkey.endpoint.ipaddr_v4, 0, 0,
					&path->pcc_addr.ipaddr_v4);
		} else {
			tlv = (struct pcep_object_tlv_header *)
				pcep_tlv_create_ipv6_lsp_identifiers(
					&path->pcc_addr.ipaddr_v6,
					&path->nbkey.endpoint.ipaddr_v6, 0, 0,
					&path->pcc_addr.ipaddr_v6);
		}
	}
	assert(tlv != NULL);
	dll_append(lsp_tlvs, tlv);
	if (path->name != NULL) {
		tlv = (struct pcep_object_tlv_header *)
			/*FIXME: Remove the typecasty when pceplib is changed
			to take a const char* */
			pcep_tlv_create_symbolic_path_name((char *)path->name,
							   strlen(path->name));
		assert(tlv != NULL);
		dll_append(lsp_tlvs, tlv);
	}
	if ((path->plsp_id != 0) && (path->binding_sid != MPLS_LABEL_NONE)) {
		memset(binding_sid_lsp_tlv_data, 0, 2);
		encoded_binding_sid = htonl(path->binding_sid << 12);
		memcpy(binding_sid_lsp_tlv_data + 2, &encoded_binding_sid, 4);
		tlv = (struct pcep_object_tlv_header *)
			pcep_tlv_create_tlv_arbitrary(
				binding_sid_lsp_tlv_data,
				sizeof(binding_sid_lsp_tlv_data),
				PCEP_OBJ_TYPE_CISCO_BSID);
		assert(tlv != NULL);
		dll_append(lsp_tlvs, tlv);
	}
	lsp = pcep_obj_create_lsp(
		path->plsp_id, path->status, path->was_created /* C Flag */,
		path->go_active /* A Flag */, path->was_removed /* R Flag */,
		path->is_synching /* S Flag */, path->is_delegated /* D Flag */,
		lsp_tlvs);
	assert(lsp != NULL);
	lsp->header.flag_p = true;
	dll_append(objs, lsp);
	/*   ERO object */
	ero_objs = dll_initialize();
	for (struct path_hop *hop = path->first_hop; hop != NULL;
	     hop = hop->next) {
		uint32_t sid;

		/* Only supporting MPLS hops with both sid and nai */
		assert(hop->is_mpls);
		assert(hop->has_sid);

		if (hop->has_attribs) {
			sid = ENCODE_SR_ERO_SID(hop->sid.mpls.label,
						hop->sid.mpls.traffic_class,
						hop->sid.mpls.is_bottom,
						hop->sid.mpls.ttl);
		} else {
			sid = ENCODE_SR_ERO_SID(hop->sid.mpls.label, 0, 0, 0);
		}

		ero_obj = NULL;
		if (hop->has_nai) {
			assert(hop->nai.type != PCEP_SR_SUBOBJ_NAI_ABSENT);
			assert(hop->nai.type
			       != PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY);
			assert(hop->nai.type != PCEP_SR_SUBOBJ_NAI_UNKNOWN);
			switch (hop->nai.type) {
			case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
				ero_obj = (struct pcep_object_ro_subobj *)
					pcep_obj_create_ro_subobj_sr_ipv4_node(
						hop->is_loose, !hop->has_sid,
						hop->has_attribs, /* C Flag */
						hop->is_mpls,     /* M Flag */
						sid,
						&hop->nai.local_addr.ipaddr_v4);
				break;
			case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
				ero_obj = (struct pcep_object_ro_subobj *)
					pcep_obj_create_ro_subobj_sr_ipv6_node(
						hop->is_loose, !hop->has_sid,
						hop->has_attribs, /* C Flag */
						hop->is_mpls,     /* M Flag */
						sid,
						&hop->nai.local_addr.ipaddr_v6);
				break;
			case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
				ero_obj = (struct pcep_object_ro_subobj *)
					pcep_obj_create_ro_subobj_sr_ipv4_adj(
						hop->is_loose, !hop->has_sid,
						hop->has_attribs, /* C Flag */
						hop->is_mpls,     /* M Flag */
						sid,
						&hop->nai.local_addr.ipaddr_v4,
						&hop->nai.remote_addr
							 .ipaddr_v4);
				break;
			case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
				ero_obj = (struct pcep_object_ro_subobj *)
					pcep_obj_create_ro_subobj_sr_ipv6_adj(
						hop->is_loose, !hop->has_sid,
						hop->has_attribs, /* C Flag */
						hop->is_mpls,     /* M Flag */
						sid,
						&hop->nai.local_addr.ipaddr_v6,
						&hop->nai.remote_addr
							 .ipaddr_v6);
				break;
			case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
				ero_obj = (struct pcep_object_ro_subobj *)
					pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
						hop->is_loose, !hop->has_sid,
						hop->has_attribs, /* C Flag */
						hop->is_mpls,     /* M Flag */
						sid,
						hop->nai.local_addr.ipaddr_v4
							.s_addr,
						hop->nai.local_iface,
						hop->nai.remote_addr.ipaddr_v4
							.s_addr,
						hop->nai.remote_iface);
				break;
			default:
				break;
			}
		}
		if (ero_obj == NULL) {
			ero_obj = (struct pcep_object_ro_subobj *)
				pcep_obj_create_ro_subobj_sr_nonai(
					hop->is_loose, sid,
					hop->has_attribs, /* C Flag */
					hop->is_mpls);    /* M Flag */
		}
		dll_append(ero_objs, ero_obj);
	}
	ero = pcep_obj_create_ero(ero_objs);
	assert(ero != NULL);
	ero->header.flag_p = true;
	dll_append(objs, ero);

	if (path->plsp_id == 0) {
		return objs;
	}

	pcep_lib_format_constraints(path, objs);

	return objs;
}

void pcep_lib_format_constraints(struct path *path, double_linked_list *objs)
{
	struct pcep_object_metric *metric;
	struct pcep_object_bandwidth *bandwidth;
	struct pcep_object_lspa *lspa;

	/* LSPA object */
	if (path->has_affinity_filters) {
		lspa = pcep_obj_create_lspa(
			path->affinity_filters[AFFINITY_FILTER_EXCLUDE_ANY - 1],
			path->affinity_filters[AFFINITY_FILTER_INCLUDE_ANY - 1],
			path->affinity_filters[AFFINITY_FILTER_INCLUDE_ALL - 1],
			DEFAULT_LSAP_SETUP_PRIO, DEFAULT_LSAP_HOLDING_PRIO,
			DEFAULT_LSAP_LOCAL_PRETECTION);
		assert(lspa != NULL);
		lspa->header.flag_p = true;
		dll_append(objs, lspa);
	}

	/* Bandwidth Objects */
	if (path->has_bandwidth) {
		/* Requested Bandwidth */
		bandwidth = pcep_obj_create_bandwidth(path->bandwidth);
		assert(bandwidth != NULL);
		bandwidth->header.flag_p = path->enforce_bandwidth;
		dll_append(objs, bandwidth);
	}

	/* Metric Objects */
	for (struct path_metric *m = path->first_metric; m != NULL;
	     m = m->next) {
		metric = pcep_obj_create_metric(m->type, m->is_bound,
						m->is_computed, m->value);
		assert(metric != NULL);
		metric->header.flag_p = m->enforce;
		dll_append(objs, metric);
	}
}

void pcep_lib_parse_open(struct pcep_caps *caps, struct pcep_object_open *open)
{
	double_linked_list *tlvs = open->header.tlv_list;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv_header;

	caps->is_stateful = false;
	caps->supported_ofs_are_known = false;
	caps->supported_ofs = 0;

	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv_header = (struct pcep_object_tlv_header *)node->data;
		switch (tlv_header->type) {
		case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
			pcep_lib_parse_open_pce_capability(caps, tlv_header);
			break;
		case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
			break;
		case PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST:
			pcep_lib_parse_open_objfun_list(caps, tlv_header);
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
				  "Unexpected OPEN's TLV %s (%u)",
				  pcep_tlv_type_name(tlv_header->type),
				  tlv_header->type);
			break;
		}
	}
}

void pcep_lib_parse_open_pce_capability(
	struct pcep_caps *caps, struct pcep_object_tlv_header *tlv_header)
{
	struct pcep_object_tlv_stateful_pce_capability *tlv;
	tlv = (struct pcep_object_tlv_stateful_pce_capability *)tlv_header;
	caps->is_stateful = tlv->flag_u_lsp_update_capability;
}

void pcep_lib_parse_open_objfun_list(struct pcep_caps *caps,
				     struct pcep_object_tlv_header *tlv_header)
{
	double_linked_list_node *node;
	struct pcep_object_tlv_of_list *tlv;
	tlv = (struct pcep_object_tlv_of_list *)tlv_header;
	uint16_t of_code;
	caps->supported_ofs_are_known = true;
	for (node = tlv->of_list->head; node != NULL; node = node->next_node) {
		of_code = *(uint16_t *)node->data;
		if (of_code >= 32) {
			zlog_warn(
				"Ignoring unexpected objective function with code %u",
				of_code);
			continue;
		}
		SET_FLAG(caps->supported_ofs, of_code);
	}
}

void pcep_lib_parse_rp(struct path *path, struct pcep_object_rp *rp)
{
	double_linked_list *tlvs = rp->header.tlv_list;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;

	if (tlvs == NULL) {
		flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
			  "Unexpected Empty RP's TLV plsp-id:(%d)",
			  path ? (int32_t)path->plsp_id : -1);
		return;
	}
	/* We ignore the other flags and priority for now */
	path->req_id = rp->request_id;
	path->has_pce_objfun = false;
	path->pce_objfun = OBJFUN_UNDEFINED;

	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *)node->data;
		switch (tlv->type) {
		case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
			// TODO: enforce the path setup type is SR_TE_PST
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
				  "Unexpected RP's TLV %s (%u)",
				  pcep_tlv_type_name(tlv->type), tlv->type);
			break;
		}
	}
}

void pcep_lib_parse_srp(struct path *path, struct pcep_object_srp *srp)
{
	double_linked_list *tlvs = srp->header.tlv_list;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;

	path->do_remove = srp->flag_lsp_remove;
	path->srp_id = srp->srp_id_number;

	if (tlvs == NULL) {
		flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
			  "Unexpected Empty SRP's TLV plsp-id:(%d)",
			  path ? (int32_t)path->plsp_id : -1);
		return;
	}
	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *)node->data;
		switch (tlv->type) {
		case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
			// TODO: enforce the path setup type is SR_TE_PST
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
				  "Unexpected SRP's TLV %s (%u)",
				  pcep_tlv_type_name(tlv->type), tlv->type);
			break;
		}
	}
}

void pcep_lib_parse_lsp(struct path *path, struct pcep_object_lsp *lsp)
{
	double_linked_list *tlvs = lsp->header.tlv_list;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;
	struct pcep_object_tlv_symbolic_path_name *name;
	struct pcep_object_tlv_arbitrary *arb_tlv;

	path->plsp_id = lsp->plsp_id;
	path->status = lsp->operational_status;
	path->go_active = lsp->flag_a;
	path->was_created = lsp->flag_c;
	path->was_removed = lsp->flag_r;
	path->is_synching = lsp->flag_s;
	path->is_delegated = lsp->flag_d;

	if (tlvs == NULL) {
		flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
			  "Unexpected Empty LSP's TLV plsp-id:(%d)",
			  path ? (int32_t)path->plsp_id : -1);
		return;
	}

	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *)node->data;
		switch (tlv->type) {
		case PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME:
			name = (struct pcep_object_tlv_symbolic_path_name *)tlv;
			pcep_lib_parse_lsp_symbolic_name(path, name);
			break;
		case PCEP_OBJ_TYPE_CISCO_BSID:
			arb_tlv = (struct pcep_object_tlv_arbitrary *)tlv;
			memcpy(&path->binding_sid, arb_tlv->data + 2,
			       sizeof(path->binding_sid));
			path->binding_sid = ntohl(path->binding_sid);
			path->binding_sid = (path->binding_sid >> 12);
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
				  "Unexpected LSP TLV %s (%u)",
				  pcep_tlv_type_name(tlv->type), tlv->type);
			break;
		}
	}
}

void pcep_lib_parse_lsp_symbolic_name(
	struct path *path, struct pcep_object_tlv_symbolic_path_name *tlv)
{
	uint16_t size = tlv->symbolic_path_name_length;
	assert(path->name == NULL);
	size = size > MAX_PATH_NAME_SIZE ? MAX_PATH_NAME_SIZE : size;
	path->name = XCALLOC(MTYPE_PCEP, size);
	strlcpy((char *)path->name, tlv->symbolic_path_name, size + 1);
}

void pcep_lib_parse_lspa(struct path *path, struct pcep_object_lspa *lspa)
{
	path->has_affinity_filters = true;
	path->affinity_filters[AFFINITY_FILTER_EXCLUDE_ANY - 1] =
		lspa->lspa_exclude_any;
	path->affinity_filters[AFFINITY_FILTER_INCLUDE_ANY - 1] =
		lspa->lspa_include_any;
	path->affinity_filters[AFFINITY_FILTER_INCLUDE_ALL - 1] =
		lspa->lspa_include_all;
}

void pcep_lib_parse_metric(struct path *path, struct pcep_object_metric *obj)
{
	struct path_metric *metric;

	metric = pcep_new_metric();
	metric->type = obj->type;
	metric->is_bound = obj->flag_b;
	metric->is_computed = obj->flag_c;
	metric->value = obj->value;
	metric->next = path->first_metric;
	path->first_metric = metric;
}

void pcep_lib_parse_endpoints_ipv4(struct path *path,
				   struct pcep_object_endpoints_ipv4 *obj)
{
	SET_IPADDR_V4(&path->pcc_addr);
	path->pcc_addr.ipaddr_v4 = obj->src_ipv4;
	SET_IPADDR_V4(&path->nbkey.endpoint);
	path->nbkey.endpoint.ipaddr_v4 = obj->dst_ipv4;
}

void pcep_lib_parse_endpoints_ipv6(struct path *path,
				   struct pcep_object_endpoints_ipv6 *obj)
{
	SET_IPADDR_V6(&path->pcc_addr);
	path->pcc_addr.ipaddr_v6 = obj->src_ipv6;
	SET_IPADDR_V6(&path->nbkey.endpoint);
	path->nbkey.endpoint.ipaddr_v6 = obj->dst_ipv6;
}

void pcep_lib_parse_vendor_info(struct path *path,
				struct pcep_object_vendor_info *obj)
{
	if (obj->enterprise_number == ENTERPRISE_NUMBER_CISCO
	    && obj->enterprise_specific_info == ENTERPRISE_COLOR_CISCO)
		path->nbkey.color = obj->enterprise_specific_info1;
	else
		path->nbkey.color = 0;
}

void pcep_lib_parse_ero(struct path *path, struct pcep_object_ro *ero)
{
	struct path_hop *hop = NULL;
	double_linked_list *objs = ero->sub_objects;
	double_linked_list_node *node;
	struct pcep_object_ro_subobj *obj;

	if (objs == NULL) {
		flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
			  "Unexpected Empty ERO's sub_obj plsp-id:(%d)",
			  path ? (int32_t)path->plsp_id : -1);
		return;
	}
	for (node = objs->tail; node != NULL; node = node->prev_node) {
		obj = (struct pcep_object_ro_subobj *)node->data;
		switch (obj->ro_subobj_type) {
		case RO_SUBOBJ_TYPE_SR:
			hop = pcep_lib_parse_ero_sr(
				hop, (struct pcep_ro_subobj_sr *)obj);
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_ERO_SUBOBJ,
				  "Unexpected ERO sub-object %s (%u)",
				  pcep_ro_type_name(obj->ro_subobj_type),
				  obj->ro_subobj_type);
			break;
		}
	}

	path->first_hop = hop;
}

struct path_hop *pcep_lib_parse_ero_sr(struct path_hop *next,
				       struct pcep_ro_subobj_sr *sr)
{
	struct path_hop *hop = NULL;
	union sid sid;

	/* Only support IPv4 node with SID */
	assert(!sr->flag_s);

	if (sr->flag_m) {
		sid.mpls = (struct sid_mpls){
			.label = GET_SR_ERO_SID_LABEL(sr->sid),
			.traffic_class = GET_SR_ERO_SID_TC(sr->sid),
			.is_bottom = GET_SR_ERO_SID_S(sr->sid),
			.ttl = GET_SR_ERO_SID_TTL(sr->sid)};
	} else {
		sid.value = sr->sid;
	}

	hop = pcep_new_hop();
	*hop = (struct path_hop){.next = next,
				 .is_loose =
					 sr->ro_subobj.flag_subobj_loose_hop,
				 .has_sid = !sr->flag_s,
				 .is_mpls = sr->flag_m,
				 .has_attribs = sr->flag_c,
				 .sid = sid,
				 .has_nai = !sr->flag_f,
				 .nai = {.type = sr->nai_type}};

	if (!sr->flag_f) {
		assert(sr->nai_list != NULL);
		double_linked_list_node *n = sr->nai_list->head;
		assert(n != NULL);
		assert(n->data != NULL);
		switch (sr->nai_type) {
		case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
			hop->nai.local_addr.ipa_type = IPADDR_V4;
			memcpy(&hop->nai.local_addr.ipaddr_v4, n->data,
			       sizeof(struct in_addr));
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
			hop->nai.local_addr.ipa_type = IPADDR_V6;
			memcpy(&hop->nai.local_addr.ipaddr_v6, n->data,
			       sizeof(struct in6_addr));
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
			hop->nai.local_addr.ipa_type = IPADDR_V4;
			memcpy(&hop->nai.local_addr.ipaddr_v4, n->data,
			       sizeof(struct in_addr));
			n = n->next_node;
			assert(n != NULL);
			assert(n->data != NULL);
			hop->nai.remote_addr.ipa_type = IPADDR_V4;
			memcpy(&hop->nai.remote_addr.ipaddr_v4, n->data,
			       sizeof(struct in_addr));
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
			hop->nai.local_addr.ipa_type = IPADDR_V6;
			memcpy(&hop->nai.local_addr.ipaddr_v6, n->data,
			       sizeof(struct in6_addr));
			n = n->next_node;
			assert(n != NULL);
			assert(n->data != NULL);
			hop->nai.remote_addr.ipa_type = IPADDR_V6;
			memcpy(&hop->nai.remote_addr.ipaddr_v6, n->data,
			       sizeof(struct in6_addr));
			break;
		case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
			hop->nai.local_addr.ipa_type = IPADDR_V4;
			memcpy(&hop->nai.local_addr.ipaddr_v4, n->data,
			       sizeof(struct in_addr));
			n = n->next_node;
			assert(n != NULL);
			assert(n->data != NULL);
			hop->nai.local_iface = *(uint32_t *)n->data;
			n = n->next_node;
			assert(n != NULL);
			assert(n->data != NULL);
			hop->nai.remote_addr.ipa_type = IPADDR_V4;
			memcpy(&hop->nai.remote_addr.ipaddr_v4, n->data,
			       sizeof(struct in_addr));
			n = n->next_node;
			assert(n != NULL);
			assert(n->data != NULL);
			hop->nai.remote_iface = *(uint32_t *)n->data;
			break;
		default:
			hop->has_nai = false;
			flog_warn(EC_PATH_PCEP_UNEXPECTED_SR_NAI,
				  "Unexpected SR segment NAI type %s (%u)",
				  pcep_nai_type_name(sr->nai_type),
				  sr->nai_type);
			break;
		}
	}

	return hop;
}

struct counters_group *copy_counter_group(struct counters_group *from)
{
	int size, i;
	struct counters_group *result;
	if (from == NULL)
		return NULL;
	assert(from->max_subgroups >= from->num_subgroups);
	result = XCALLOC(MTYPE_PCEP, sizeof(*result));
	memcpy(result, from, sizeof(*result));
	size = sizeof(struct counters_subgroup *) * (from->max_subgroups + 1);
	result->subgroups = XCALLOC(MTYPE_PCEP, size);
	for (i = 0; i <= from->max_subgroups; i++)
		result->subgroups[i] =
			copy_counter_subgroup(from->subgroups[i]);
	return result;
}

struct counters_subgroup *copy_counter_subgroup(struct counters_subgroup *from)
{
	int size, i;
	struct counters_subgroup *result;
	if (from == NULL)
		return NULL;
	assert(from->max_counters >= from->num_counters);
	result = XCALLOC(MTYPE_PCEP, sizeof(*result));
	memcpy(result, from, sizeof(*result));
	size = sizeof(struct counter *) * (from->max_counters + 1);
	result->counters = XCALLOC(MTYPE_PCEP, size);
	for (i = 0; i <= from->max_counters; i++)
		result->counters[i] = copy_counter(from->counters[i]);
	return result;
}

struct counter *copy_counter(struct counter *from)
{
	struct counter *result;
	if (from == NULL)
		return NULL;
	result = XCALLOC(MTYPE_PCEP, sizeof(*result));
	memcpy(result, from, sizeof(*result));
	return result;
}

void free_counter_group(struct counters_group *group)
{
	int i;
	if (group == NULL)
		return;
	for (i = 0; i <= group->max_subgroups; i++)
		free_counter_subgroup(group->subgroups[i]);
	XFREE(MTYPE_PCEP, group->subgroups);
	XFREE(MTYPE_PCEP, group);
}

void free_counter_subgroup(struct counters_subgroup *subgroup)
{
	int i;
	if (subgroup == NULL)
		return;
	for (i = 0; i <= subgroup->max_counters; i++)
		free_counter(subgroup->counters[i]);
	XFREE(MTYPE_PCEP, subgroup->counters);
	XFREE(MTYPE_PCEP, subgroup);
}

void free_counter(struct counter *counter)
{
	if (counter == NULL)
		return;
	XFREE(MTYPE_PCEP, counter);
}
