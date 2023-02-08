// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#ifndef _PATH_PCEP_DEBUG_H_
#define _PATH_PCEP_DEBUG_H_

#include "pathd/path_debug.h"
#include "pceplib/pcep_pcc_api.h"
#include "pceplib/pcep_msg_objects.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_pcc.h"
#include "pathd/path_pcep_lib.h"

const char *pcc_status_name(enum pcc_status status);

const char *pcep_error_type_name(enum pcep_error_type error_type);
const char *pcep_error_value_name(enum pcep_error_type error_type,
				  enum pcep_error_value error_value);
const char *pcep_event_type_name(pcep_event_type event_type);
const char *pcep_message_type_name(enum pcep_message_types pcep_message_type);
const char *pcep_object_class_name(enum pcep_object_classes obj_class);
const char *pcep_object_type_name(enum pcep_object_classes obj_class,
				  enum pcep_object_types obj_type);
const char *pcep_lsp_status_name(enum pcep_lsp_operational_status status);
const char *pcep_tlv_type_name(enum pcep_object_tlv_types tlv_type);
const char *pcep_ro_type_name(enum pcep_ro_subobj_types ro_type);
const char *pcep_nai_type_name(enum pcep_sr_subobj_nai nai_type);
const char *pcep_metric_type_name(enum pcep_metric_types type);
const char *pcep_nopath_tlv_err_code_name(enum pcep_nopath_tlv_err_codes code);

const char *format_objfun_set(uint32_t flags);
const char *format_pcc_opts(struct pcc_opts *ops);
const char *format_pcc_state(struct pcc_state *state);
const char *format_ctrl_state(struct ctrl_state *state);
const char *format_path(struct path *path);
const char *format_pcep_event(pcep_event *event);
const char *format_pcep_message(struct pcep_message *msg);

#endif // _PATH_PCEP_DEBUG_H_
