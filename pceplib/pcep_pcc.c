// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 * Sample PCC implementation
 */

#include <zebra.h>

#include <netdb.h> // gethostbyname
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pcep_pcc_api.h"
#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

/*
 * PCEP PCC design spec:
 * https://docs.google.com/presentation/d/1DYc3ZhYA1c_qg9A552HjhneJXQKdh_yrKW6v3NRYPtnbw/edit?usp=sharing
 */
#define MAX_SRC_IP_STR 40
#define MAX_DST_IP_STR 40
struct cmd_line_args {
	char src_ip_str[MAX_SRC_IP_STR];
	char dest_ip_str[MAX_DST_IP_STR];
	short src_tcp_port;
	short dest_tcp_port;
	char tcp_md5_str[PCEP_MD5SIG_MAXKEYLEN]; /* RFC 2385 */
	bool is_ipv6;
	bool eventpoll; /* poll for pcep_event's, or use callback (default) */
};

bool pcc_active_ = true;
pcep_session *session = NULL;
struct cmd_line_args *cmd_line_args = NULL;
/* pcep_event callback variables */
bool pcep_event_condition = false;
struct pcep_event *event = NULL;
pthread_mutex_t pcep_event_mutex;
pthread_cond_t pcep_event_cond_var;

static const char DEFAULT_DEST_HOSTNAME[] = "localhost";
static const char DEFAULT_DEST_HOSTNAME_IPV6[] = "ip6-localhost";
static const short DEFAULT_SRC_TCP_PORT = 4999;

// Private fn's
struct cmd_line_args *get_cmdline_args(int argc, char *argv[]);
void handle_signal_action(int sig_number);
void send_pce_path_request_message(pcep_session *session);
void send_pce_report_message(pcep_session *session);
void print_queue_event(struct pcep_event *event);
void pcep_event_callback(void *cb_data, pcep_event *e);

struct cmd_line_args *get_cmdline_args(int argc, char *argv[])
{
	/* Allocate and set default values */
	struct cmd_line_args *cmd_line_args =
		malloc(sizeof(struct cmd_line_args));
	memset(cmd_line_args, 0, sizeof(struct cmd_line_args));
	strlcpy(cmd_line_args->dest_ip_str, DEFAULT_DEST_HOSTNAME,
		MAX_DST_IP_STR);
	cmd_line_args->src_tcp_port = DEFAULT_SRC_TCP_PORT;
	cmd_line_args->is_ipv6 = false;

	/* Parse the cmd_line args:
	 * -ipv6
	 * -srcip localhost
	 * -destip 192.168.0.2
	 * -srcport 4999
	 * -dstport 4189
	 * -tcpmd5 hello
	 * -event_poll */
	int i = 1;
	for (; i < argc; ++i) {
		if (strcmp(argv[i], "-help") == 0
		    || strcmp(argv[i], "--help") == 0
		    || strcmp(argv[i], "-h") == 0) {
			pcep_log(
				LOG_INFO,
				"%s: pcep_pcc [-ipv6] [-srcip localhost] [-destip 192.168.0.1] [-srcport 4999] [-dstport 4189] [-tcpmd5 authstr] [-eventpoll]",
				__func__);
			free(cmd_line_args);
			return NULL;
		} else if (strcmp(argv[i], "-ipv6") == 0) {
			cmd_line_args->is_ipv6 = true;
			if (argc == 2) {
				strlcpy(cmd_line_args->dest_ip_str,
					DEFAULT_DEST_HOSTNAME_IPV6,
					MAX_DST_IP_STR);
			}
		} else if (strcmp(argv[i], "-eventpoll") == 0) {
			cmd_line_args->eventpoll = true;
		} else if (strcmp(argv[i], "-srcip") == 0) {
			if (argc >= i + 2) {
				strlcpy(cmd_line_args->src_ip_str, argv[++i],
					MAX_SRC_IP_STR);
			} else {
				pcep_log(
					LOG_ERR,
					"%s: Invalid number of cmd_line_args for \"-srcip\"",
					__func__);
				free(cmd_line_args);
				return NULL;
			}
		} else if (strcmp(argv[i], "-destip") == 0) {
			if (argc >= i + 2) {
				strlcpy(cmd_line_args->dest_ip_str, argv[++i],
					MAX_DST_IP_STR);
			} else {
				pcep_log(
					LOG_ERR,
					"%s: Invalid number of cmd_line_args for \"-destip\"",
					__func__);
				free(cmd_line_args);
				return NULL;
			}
		} else if (strcmp(argv[i], "-srcport") == 0) {
			if (argc >= i + 2) {
				cmd_line_args->src_tcp_port = atoi(argv[++i]);
			} else {
				pcep_log(
					LOG_ERR,
					"%s: Invalid number of cmd_line_args for \"-srcport\"",
					__func__);
				free(cmd_line_args);
				return NULL;
			}
		} else if (strcmp(argv[i], "-destport") == 0) {
			if (argc >= i + 2) {
				cmd_line_args->dest_tcp_port = atoi(argv[++i]);
			} else {
				pcep_log(
					LOG_ERR,
					"%s: Invalid number of cmd_line_args for \"-destport\"",
					__func__);
				free(cmd_line_args);
				return NULL;
			}
		} else if (strcmp(argv[i], "-tcpmd5") == 0) {
			if (argc >= i + 2) {
				strlcpy(cmd_line_args->tcp_md5_str, argv[++i],
					sizeof(cmd_line_args->tcp_md5_str));
			} else {
				pcep_log(
					LOG_ERR,
					"%s: Invalid number of cmd_line_args for \"-tcpmd5\"",
					__func__);
				free(cmd_line_args);
				return NULL;
			}
		} else {
			pcep_log(LOG_ERR, "%s: Invalid cmd_line_arg[%d] = %s",
				 __func__, i, argv[i]);
			free(cmd_line_args);
			return NULL;
		}
	}

	return cmd_line_args;
}

void handle_signal_action(int sig_number)
{
	if (sig_number == SIGINT) {
		pcep_log(LOG_INFO, "%s: SIGINT was caught!", __func__);
		pcc_active_ = false;
		if (cmd_line_args->eventpoll == false) {
			pthread_mutex_lock(&pcep_event_mutex);
			pcep_event_condition = true;
			pthread_cond_signal(&pcep_event_cond_var);
			pthread_mutex_unlock(&pcep_event_mutex);
		}
	} else if (sig_number == SIGUSR1) {
		pcep_log(LOG_INFO, "%s: SIGUSR1 was caught, dumping counters",
			 __func__);
		dump_pcep_session_counters(session);
		pceplib_memory_dump();
	} else if (sig_number == SIGUSR2) {
		pcep_log(LOG_INFO, "%s: SIGUSR2 was caught, reseting counters",
			 __func__);
		reset_pcep_session_counters(session);
	}
}

static int setup_signals(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal_action;
	if (sigaction(SIGINT, &sa, 0) != 0) {
		perror("sigaction()");
		return -1;
	}

	if (sigaction(SIGUSR1, &sa, 0) != 0) {
		perror("sigaction()");
		return -1;
	}

	if (sigaction(SIGUSR2, &sa, 0) != 0) {
		perror("sigaction()");
		return -1;
	}

	return 0;
}

void send_pce_path_request_message(pcep_session *session)
{
	struct in_addr src_ipv4;
	struct in_addr dst_ipv4;
	inet_pton(AF_INET, "1.2.3.4", &src_ipv4);
	inet_pton(AF_INET, "10.20.30.40", &dst_ipv4);

	struct pcep_object_rp *rp_object =
		pcep_obj_create_rp(1, false, false, false, false, 42, NULL);
	struct pcep_object_endpoints_ipv4 *ep_object =
		pcep_obj_create_endpoint_ipv4(&src_ipv4, &dst_ipv4);

	struct pcep_message *path_request =
		pcep_msg_create_request(rp_object, ep_object, NULL);
	send_message(session, path_request, true);
}

void send_pce_report_message(pcep_session *session)
{
	double_linked_list *report_list = dll_initialize();

	/* SRP Path Setup Type TLV */
	struct pcep_object_tlv_path_setup_type *pst_tlv =
		pcep_tlv_create_path_setup_type(SR_TE_PST);
	double_linked_list *srp_tlv_list = dll_initialize();
	dll_append(srp_tlv_list, pst_tlv);

	/*
	 * Create the SRP object
	 */
	uint32_t srp_id_number = 0x10203040;
	struct pcep_object_header *obj =
		(struct pcep_object_header *)pcep_obj_create_srp(
			false, srp_id_number, srp_tlv_list);
	if (obj == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: send_pce_report_message SRP object was NULL",
			 __func__);
		dll_destroy_with_data(report_list);
		return;
	}
	dll_append(report_list, obj);

	/* LSP Symbolic path name TLV */
	char symbolic_path_name[] = "second-default";
	struct pcep_object_tlv_symbolic_path_name *spn_tlv =
		pcep_tlv_create_symbolic_path_name(symbolic_path_name, 14);
	double_linked_list *lsp_tlv_list = dll_initialize();
	dll_append(lsp_tlv_list, spn_tlv);

	/* LSP IPv4 LSP ID TLV */
	struct in_addr ipv4_tunnel_sender;
	struct in_addr ipv4_tunnel_endpoint;
	inet_pton(AF_INET, "9.9.1.1", &ipv4_tunnel_sender);
	inet_pton(AF_INET, "9.9.2.1", &ipv4_tunnel_endpoint);
	struct pcep_object_tlv_ipv4_lsp_identifier *ipv4_lsp_id_tlv =
		pcep_tlv_create_ipv4_lsp_identifiers(&ipv4_tunnel_sender,
						     &ipv4_tunnel_endpoint, 42,
						     1, NULL);
	dll_append(lsp_tlv_list, ipv4_lsp_id_tlv);

	/*
	 * Create the LSP object
	 */
	uint32_t plsp_id = 42;
	enum pcep_lsp_operational_status lsp_status =
		PCEP_LSP_OPERATIONAL_ACTIVE;
	bool c_flag = false; /* Lsp was created by PcInitiate msg */
	bool a_flag = false; /* Admin state, active / inactive */
	bool r_flag = false; /* true if LSP has been removed */
	bool s_flag = true;  /* Synchronization */
	bool d_flag = false; /* Delegate LSP to PCE */
	obj = (struct pcep_object_header *)pcep_obj_create_lsp(
		plsp_id, lsp_status, c_flag, a_flag, r_flag, s_flag, d_flag,
		lsp_tlv_list);
	if (obj == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: send_pce_report_message LSP object was NULL",
			 __func__);
		dll_destroy_with_data(report_list);
		return;
	}
	dll_append(report_list, obj);

	/* Create 2 ERO NONAI sub-objects */
	double_linked_list *ero_subobj_list = dll_initialize();
	struct pcep_ro_subobj_sr *sr_subobj_nonai1 =
		pcep_obj_create_ro_subobj_sr_nonai(false, 503808, true, true);
	dll_append(ero_subobj_list, sr_subobj_nonai1);

	struct pcep_ro_subobj_sr *sr_subobj_nonai2 =
		pcep_obj_create_ro_subobj_sr_nonai(false, 1867776, true, true);
	dll_append(ero_subobj_list, sr_subobj_nonai2);

	/* Create ERO IPv4 node sub-object */
	struct in_addr sr_subobj_ipv4;
	inet_pton(AF_INET, "9.9.9.1", &sr_subobj_ipv4);
	struct pcep_ro_subobj_sr *sr_subobj_ipv4node =
		pcep_obj_create_ro_subobj_sr_ipv4_node(
			false, false, false, true, 16060, &sr_subobj_ipv4);
	if (sr_subobj_ipv4node == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: send_pce_report_message ERO sub-object was NULL",
			 __func__);
		return;
	}
	dll_append(ero_subobj_list, sr_subobj_ipv4node);

	/*
	 * Create the ERO object
	 */
	obj = (struct pcep_object_header *)pcep_obj_create_ero(ero_subobj_list);
	if (obj == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: send_pce_report_message ERO object was NULL",
			 __func__);
		dll_destroy_with_data(report_list);
		return;
	}
	dll_append(report_list, obj);

	/*
	 * Create the Metric object
	 */
	obj = (struct pcep_object_header *)pcep_obj_create_metric(
		PCEP_METRIC_TE, false, true, 16.0);
	dll_append(report_list, obj);

	/* Create and send the report message */
	struct pcep_message *report_msg = pcep_msg_create_report(report_list);
	send_message(session, report_msg, true);
}

void print_queue_event(struct pcep_event *event)
{
	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] Received Event: type [%s] on session [%d] occurred at [%ld]",
		__func__, time(NULL), pthread_self(),
		get_event_type_str(event->event_type),
		event->session->session_id, event->event_time);

	if (event->event_type == MESSAGE_RECEIVED) {
		pcep_log(
			LOG_INFO, "%s: \t Event message type [%s]", __func__,
			get_message_type_str(event->message->msg_header->type));
	}
}

/* Called by pcep_session_logic when pcep_event's are ready */
void pcep_event_callback(void *cb_data, pcep_event *e)
{
	(void)cb_data;
	pcep_log(LOG_NOTICE, "%s: [%ld-%ld] pcep_event_callback", __func__,
		 time(NULL), pthread_self());
	pthread_mutex_lock(&pcep_event_mutex);
	event = e;
	pcep_event_condition = true;
	pthread_cond_signal(&pcep_event_cond_var);
	pthread_mutex_unlock(&pcep_event_mutex);
}

int main(int argc, char **argv)
{
	pcep_log(LOG_NOTICE, "%s: [%ld-%ld] starting pcc_pcep example client",
		 __func__, time(NULL), pthread_self());

	cmd_line_args = get_cmdline_args(argc, argv);
	if (cmd_line_args == NULL) {
		return -1;
	}

	setup_signals();

	if (cmd_line_args->eventpoll == false) {
		struct pceplib_infra_config infra_config;
		memset(&infra_config, 0, sizeof(infra_config));
		infra_config.pcep_event_func = pcep_event_callback;
		if (!initialize_pcc_infra(&infra_config)) {
			pcep_log(LOG_ERR,
				 "%s: Error initializing PCC with infra.",
				 __func__);
			return -1;
		}
	} else {
		if (!initialize_pcc()) {
			pcep_log(LOG_ERR, "%s: Error initializing PCC.",
				 __func__);
			return -1;
		}
	}

	pcep_configuration *config = create_default_pcep_configuration();
	config->pcep_msg_versioning->draft_ietf_pce_segment_routing_07 = true;
	config->src_pcep_port = cmd_line_args->src_tcp_port;
	config->is_tcp_auth_md5 = true;

	strlcpy(config->tcp_authentication_str, cmd_line_args->tcp_md5_str,
		sizeof(config->tcp_authentication_str));

	int af = (cmd_line_args->is_ipv6 ? AF_INET6 : AF_INET);
	struct hostent *host_info =
		gethostbyname2(cmd_line_args->dest_ip_str, af);
	if (host_info == NULL) {
		pcep_log(LOG_ERR, "%s: Error getting IP address.", __func__);
		return -1;
	}

	if (cmd_line_args->is_ipv6) {
		struct in6_addr host_address;
		memcpy(&host_address, host_info->h_addr, host_info->h_length);
		session = connect_pce_ipv6(config, &host_address);
	} else {
		struct in_addr host_address;
		memcpy(&host_address, host_info->h_addr, host_info->h_length);
		session = connect_pce(config, &host_address);
	}

	if (session == NULL) {
		pcep_log(LOG_WARNING, "%s: Error in connect_pce.", __func__);
		destroy_pcep_configuration(config);
		return -1;
	}

	sleep(2);

	send_pce_report_message(session);
	/*send_pce_path_request_message(session);*/

	/* Wait for pcep_event's either by polling the event queue or by
	 * callback */
	if (cmd_line_args->eventpoll == true) {
		/* Poll the pcep_event queue*/
		while (pcc_active_) {
			if (event_queue_is_empty() == false) {
				struct pcep_event *event =
					event_queue_get_event();
				print_queue_event(event);
				destroy_pcep_event(event);
			}

			sleep(5);
		}
	} else {
		/* Get events via callback and conditional variable */
		pthread_mutex_init(&pcep_event_mutex, NULL);
		pthread_cond_init(&pcep_event_cond_var, NULL);
		while (pcc_active_) {
			pthread_mutex_lock(&pcep_event_mutex);

			/* this internal loop helps avoid spurious interrupts */
			while (!pcep_event_condition) {
				pthread_cond_wait(&pcep_event_cond_var,
						  &pcep_event_mutex);
			}

			/* Check if we have been interrupted by SIGINT */
			if (pcc_active_) {
				print_queue_event(event);
				destroy_pcep_event(event);
			}

			pcep_event_condition = false;
			pthread_mutex_unlock(&pcep_event_mutex);
		}

		pthread_mutex_destroy(&pcep_event_mutex);
		pthread_cond_destroy(&pcep_event_cond_var);
	}

	pcep_log(LOG_NOTICE, "%s: Disconnecting from PCE", __func__);
	disconnect_pce(session);
	destroy_pcep_configuration(config);
	free(cmd_line_args);

	if (!destroy_pcc()) {
		pcep_log(LOG_NOTICE, "%s: Error stopping PCC.", __func__);
	}

	pceplib_memory_dump();

	return 0;
}
