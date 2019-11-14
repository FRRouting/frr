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

#include <stdbool.h>
#include <time.h>

#include "printfrr.h"

#include "pathd/path_pcep_debug.h"

#ifdef __GNUC__
#define THREAD_DATA __thread
#else
#define THREAD_DATA
#endif

#define DEBUG_IDENT_SIZE 4
#define DEBUG_BUFF_SIZE 4096
#define PCEP_FORMAT_INIT() _debug_buff[0] = 0;
#define PCEP_FORMAT(fmt, ...) csnprintfrr(_debug_buff, DEBUG_BUFF_SIZE, fmt, ##__VA_ARGS__);
#define PCEP_FORMAT_FINI() _debug_buff;
THREAD_DATA char _debug_buff[DEBUG_BUFF_SIZE];

static void _format_pcc_opts(int ps, pcc_opts_t *ops);
static void _format_pcc_state(int ps, pcc_state_t *state);
static void _format_ctrl_state(int ps, ctrl_state_t *state);
static void _format_pcep_event(int ps, pcep_event *event);
static void _format_pcep_message(int ps, pcep_message *msg);
static void _format_pcep_header(int ps, struct pcep_header *header);
static void _format_pcep_objects(int ps, double_linked_list *objs);
static void _format_pcep_object(int ps, struct pcep_object_header *obj);
static void _format_pcep_object_header(int ps, struct pcep_object_header *obj);

const char *pcc_status_name(pcc_status_t status)
{
	switch (status) {
		case INITIALIZED: return "INITIALIZED";
		case DISCONNECTED: return "DISCONNECTED";
		case CONNECTING: return "CONNECTING";
		case CONNECTED: return "CONNECTED";
		default: return "UNKNOWN";
	}
}

const char *pcep_event_type_name(pcep_event_type event_type)
{
	switch (event_type) {
		case MESSAGE_RECEIVED:
			return "MESSAGE_RECEIVED";
		case PCE_CLOSED_SOCKET:
			return "PCE_CLOSED_SOCKET";
		case PCE_SENT_PCEP_CLOSE:
			return "PCE_SENT_PCEP_CLOSE";
		case PCE_DEAD_TIMER_EXPIRED:
			return "PCE_DEAD_TIMER_EXPIRED";
		case PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED:
			return "PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED";
		case PCC_CONNECTED_TO_PCE:
			return "PCC_CONNECTED_TO_PCE";
		case PCC_PCEP_SESSION_CLOSED:
			return "PCC_PCEP_SESSION_CLOSED";
		case PCC_RCVD_INVALID_OPEN:
			return "PCC_RCVD_INVALID_OPEN";
		case PCC_RCVD_MAX_INVALID_MSGS:
			return "PCC_RCVD_MAX_INVALID_MSGS";
		case PCC_RCVD_MAX_UNKOWN_MSGS:
			return "PCC_RCVD_MAX_UNKOWN_MSGS";
		default:
			return "UNKNOWN";
	}
}

const char *pcep_message_type_name(enum pcep_types pcep_type)
{
	switch (pcep_type) {
		case PCEP_TYPE_OPEN: return "PCEP_TYPE_OPEN";
		case PCEP_TYPE_KEEPALIVE: return "PCEP_TYPE_KEEPALIVE";
		case PCEP_TYPE_PCREQ: return "PCEP_TYPE_PCREQ";
		case PCEP_TYPE_PCREP: return "PCEP_TYPE_PCREP";
		case PCEP_TYPE_PCNOTF: return "PCEP_TYPE_PCNOTF";
		case PCEP_TYPE_ERROR: return "PCEP_TYPE_ERROR";
		case PCEP_TYPE_CLOSE: return "PCEP_TYPE_CLOSE";
		case PCEP_TYPE_REPORT: return "PCEP_TYPE_REPORT";
		case PCEP_TYPE_UPDATE: return "PCEP_TYPE_UPDATE";
		case PCEP_TYPE_INITIATE: return "PCEP_TYPE_INITIATE";
		default: return "UNKNOWN";
	}
}

const char *pcep_object_class_name(enum pcep_object_class obj_class)
{
	switch (obj_class) {
		case PCEP_OBJ_CLASS_OPEN: return "PCEP_OBJ_CLASS_OPEN";
		case PCEP_OBJ_CLASS_RP: return "PCEP_OBJ_CLASS_RP";
		case PCEP_OBJ_CLASS_NOPATH: return "PCEP_OBJ_CLASS_NOPATH";
		case PCEP_OBJ_CLASS_ENDPOINTS: return "PCEP_OBJ_CLASS_ENDPOINTS";
		case PCEP_OBJ_CLASS_BANDWIDTH: return "PCEP_OBJ_CLASS_BANDWIDTH";
		case PCEP_OBJ_CLASS_METRIC: return "PCEP_OBJ_CLASS_METRIC";
		case PCEP_OBJ_CLASS_ERO: return "PCEP_OBJ_CLASS_ERO";
		case PCEP_OBJ_CLASS_RRO: return "PCEP_OBJ_CLASS_RRO";
		case PCEP_OBJ_CLASS_LSPA: return "PCEP_OBJ_CLASS_LSPA";
		case PCEP_OBJ_CLASS_IRO: return "PCEP_OBJ_CLASS_IRO";
		case PCEP_OBJ_CLASS_SVEC: return "PCEP_OBJ_CLASS_SVEC";
		case PCEP_OBJ_CLASS_NOTF: return "PCEP_OBJ_CLASS_NOTF";
		case PCEP_OBJ_CLASS_ERROR: return "PCEP_OBJ_CLASS_ERROR";
		case PCEP_OBJ_CLASS_CLOSE: return "PCEP_OBJ_CLASS_CLOSE";
		case PCEP_OBJ_CLASS_LSP: return "PCEP_OBJ_CLASS_LSP";
		case PCEP_OBJ_CLASS_SRP: return "PCEP_OBJ_CLASS_SRP";
		default: return "UNKNOWN";
	}
}

const char *pcep_object_type_name(enum pcep_object_class obj_class,
				  enum pcep_object_types obj_type)
{
	switch (obj_class) {
		case PCEP_OBJ_CLASS_OPEN:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_OPEN:
					return "PCEP_OBJ_TYPE_OPEN";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_RP:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_RP:
					return "PCEP_OBJ_TYPE_RP";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_NOPATH:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_NOPATH:
					return "PCEP_OBJ_TYPE_NOPATH";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_ENDPOINTS:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_ENDPOINT_IPV4:
					return "PCEP_OBJ_TYPE_ENDPOINT_IPV4";
				case PCEP_OBJ_TYPE_ENDPOINT_IPV6:
					return "PCEP_OBJ_TYPE_ENDPOINT_IPV6";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_BANDWIDTH:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_BANDWIDTH_REQ:
					return "PCEP_OBJ_TYPE_BANDWIDTH_REQ";
				case PCEP_OBJ_TYPE_BANDWIDTH_TELSP:
					return "PCEP_OBJ_TYPE_BANDWIDTH_TELSP";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_METRIC:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_METRIC:
					return "PCEP_OBJ_TYPE_METRIC";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_ERO:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_ERO:
					return "PCEP_OBJ_TYPE_ERO";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_RRO:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_RRO:
					return "PCEP_OBJ_TYPE_RRO";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_LSPA:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_LSPA:
					return "PCEP_OBJ_TYPE_LSPA";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_IRO:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_IRO:
					return "PCEP_OBJ_TYPE_IRO";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_SVEC:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_SVEC:
					return "PCEP_OBJ_TYPE_SVEC";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_NOTF:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_NOTF:
					return "PCEP_OBJ_TYPE_NOTF";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_ERROR:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_ERROR:
					return "PCEP_OBJ_TYPE_ERROR";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_CLOSE:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_CLOSE:
					return "PCEP_OBJ_TYPE_CLOSE";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_LSP:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_LSP:
					return "PCEP_OBJ_TYPE_LSP";
				default: return "UNKNOWN";
			}
		case PCEP_OBJ_CLASS_SRP:
			switch (obj_type) {
				case PCEP_OBJ_TYPE_SRP:
					return "PCEP_OBJ_TYPE_SRP";
				default: return "UNKNOWN";
			}
		default: return "UNKNOWN";
	}
}

const char *format_pcc_opts(pcc_opts_t *opts)
{
	PCEP_FORMAT_INIT();
	_format_pcc_opts(0, opts);
	return PCEP_FORMAT_FINI();
}

const char *format_pcc_state(pcc_state_t *state)
{
	PCEP_FORMAT_INIT();
	_format_pcc_state(0, state);
	return PCEP_FORMAT_FINI();
}

const char *format_ctrl_state(ctrl_state_t *state)
{
	PCEP_FORMAT_INIT();
	_format_ctrl_state(0, state);
	return PCEP_FORMAT_FINI();
}

const char *format_pcep_event(pcep_event *event)
{
	PCEP_FORMAT_INIT();
	_format_pcep_event(0, event);
	return PCEP_FORMAT_FINI();
}

const char *format_pcep_message(pcep_message *msg)
{
	PCEP_FORMAT_INIT();
	_format_pcep_message(0, msg);
	return PCEP_FORMAT_FINI();
}

void _format_pcc_opts(int ps, pcc_opts_t *opts)
{
	if (NULL == opts) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("{\n");
		PCEP_FORMAT("%*saddr = %pI4\n", ps2, "", &opts->addr);
		PCEP_FORMAT("%*sport = %i\n", ps2, "", opts->port);
		PCEP_FORMAT("%*s}\n", ps, "");
	}
}

void _format_pcc_state(int ps, pcc_state_t *state)
{
	if (NULL == state) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("{\n");
		PCEP_FORMAT("%*sstatus = %s\n", ps2, "",
			    pcc_status_name(state->status));
		PCEP_FORMAT("%*sopts = ", ps2, "");
		_format_pcc_opts(ps2, state->opts);
		if (NULL == state->sess) {
			PCEP_FORMAT("%*ssess = NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*ssess = <PCC SESSION %p>\n", ps2, "",
				    state->sess);
		}
		PCEP_FORMAT("%*s}\n", ps, "");
	}
}

void _format_ctrl_state(int ps, ctrl_state_t *state)
{
	if (NULL == state) {
		PCEP_FORMAT("NULL\n");
	} else {
		int i;
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int ps3 = ps2 + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("{\n");
		if (NULL == state->main) {
			PCEP_FORMAT("%*smain = NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*smain = <THREAD MASTER %p>\n", ps2, "",
				    state->main);
		}
		if (NULL == state->self) {
			PCEP_FORMAT("%*sself = NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*sself = <THREAD MASTER %p>\n", ps2, "",
				    state->self);
		}
		if (NULL == state->t_poll) {
			PCEP_FORMAT("%*st_poll = NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*st_poll = <THREAD %p>\n", ps2, "",
				    state->t_poll);
		}
		PCEP_FORMAT("%*spcc_count = %d\n", ps2, "", state->pcc_count);
		PCEP_FORMAT("%*spcc = [\n", ps2, "");
		for (i = 0; i < state->pcc_count; i++) {
			PCEP_FORMAT("%*s[%d] = ", ps3, "", i);
			_format_pcc_state(ps3, state->pcc[i]);
		}
		PCEP_FORMAT("%*s]\n", ps2, "");
		PCEP_FORMAT("%*s}\n", ps, "");
	}
}

void _format_pcep_event(int ps, pcep_event *event)
{
	if (NULL == event) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("{\n");
		PCEP_FORMAT("%*sevent_type = %s\n", ps2, "",
			    pcep_event_type_name(event->event_type));
		PCEP_FORMAT("%*sevent_time = %s", ps2, "",
			    ctime(&event->event_time));
		if (NULL == event->session) {
			PCEP_FORMAT("%*ssession = NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*ssession = <PCC SESSION %p>\n", ps2, "",
				    event->session);
		}
		PCEP_FORMAT("%*smessage = ", ps2, "");
		_format_pcep_message(ps2, event->message);
		PCEP_FORMAT("%*s}\n", ps, "");
	}
}

void _format_pcep_message(int ps, pcep_message *msg)
{
	if (NULL == msg) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("{\n");
		PCEP_FORMAT("%*sheader = ", ps2, "");
		_format_pcep_header(ps2, &msg->header);
		PCEP_FORMAT("%*sobj_list = ", ps2, "");
		_format_pcep_objects(ps2, msg->obj_list);
		PCEP_FORMAT("%*s}\n", ps, "");
	}
}

void _format_pcep_header(int ps, struct pcep_header *header)
{
	int ps2 = ps + DEBUG_IDENT_SIZE;
	PCEP_FORMAT("{\n");
	PCEP_FORMAT("%*sver_flags = %u\n", ps2, "", header->ver_flags);
	PCEP_FORMAT("%*stype = %s\n", ps2, "",
		    pcep_message_type_name(header->type));
	PCEP_FORMAT("%*ssize = %u\n", ps2, "", header->length);
	PCEP_FORMAT("%*s}\n", ps, "");
}

void _format_pcep_objects(int ps, double_linked_list *objs)
{
	if (NULL == objs) {
		PCEP_FORMAT("NULL\n");
	} else {
		double_linked_list_node *node;
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int i;
		PCEP_FORMAT("[\n");
		for (node = objs->head, i = 0;
		     node != NULL;
		     node = node->next_node, i++) {
			int ps3 = ps2 + DEBUG_IDENT_SIZE;
			struct pcep_object_header *obj =
				(struct pcep_object_header *) node->data;
			PCEP_FORMAT("%*s[%d] = ", ps3, "", i);
			_format_pcep_object(ps3, obj);
		}
		PCEP_FORMAT("%*s]\n", ps, "");
	}
}

void _format_pcep_object(int ps, struct pcep_object_header *obj)
{
	if (NULL == obj) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("{\n");
		PCEP_FORMAT("%*sheader = ", ps2, "");
		_format_pcep_object_header(ps2, obj);
		PCEP_FORMAT("%*s}\n", ps, "");
	}
}

void _format_pcep_object_header(int ps, struct pcep_object_header *obj)
{
	int ps2 = ps + DEBUG_IDENT_SIZE;
	PCEP_FORMAT("{\n");
	PCEP_FORMAT("%*sobject_class = %s\n", ps2, "",
		    pcep_object_class_name(obj->object_class));
	PCEP_FORMAT("%*sobject_flags = %u\n", ps2, "", obj->object_flags);
	PCEP_FORMAT("%*sobject_type = %s\n", ps2, "",
		    pcep_object_type_name(obj->object_class, obj->object_type));
	PCEP_FORMAT("%*sobject_length = %u\n", ps2, "", obj->object_length);
	PCEP_FORMAT("%*s}\n", ps, "");
}