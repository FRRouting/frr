/*
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
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

#include "northbound.h"
#include "log.h"

#include "isisd/isisd.h"
#include "isisd/isis_nb.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"

/*
 * Helper functions.
 */
static void notif_prep_instance_hdr(const char *xpath,
				    const struct isis_area *area,
				    const char *routing_instance,
				    struct list *args)
{
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/routing-instance", xpath);
	data = yang_data_new_string(xpath_arg, routing_instance);
	listnode_add(args, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/routing-protocol-name",
		 xpath);
	data = yang_data_new_string(xpath_arg, area->area_tag);
	listnode_add(args, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/isis-level", xpath);
	data = yang_data_new_enum(xpath_arg, area->is_type);
	listnode_add(args, data);
}

static void notif_prepr_iface_hdr(const char *xpath,
				  const struct isis_circuit *circuit,
				  struct list *args)
{
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface-name", xpath);
	data = yang_data_new_string(xpath_arg, circuit->interface->name);
	listnode_add(args, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface-level", xpath);
	data = yang_data_new_enum(xpath_arg, circuit->is_type);
	listnode_add(args, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/extended-circuit-id", xpath);
	/* we do not seem to have the extended version of the circuit_id */
	data = yang_data_new_uint32(xpath_arg, (uint32_t)circuit->circuit_id);
	listnode_add(args, data);
}

/*
 * XPath: /frr-isisd:database-overload
 */
void isis_notif_db_overload(const struct isis_area *area, bool overload)
{
	const char *xpath = "/frr-isisd:database-overload";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/overload", xpath);
	data = yang_data_new_enum(xpath_arg, !!overload);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:lsp-too-large
 */
void isis_notif_lsp_too_large(const struct isis_circuit *circuit,
			      uint32_t pdu_size, const char *lsp_id)
{
	const char *xpath = "/frr-isisd:lsp-too-large";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/pdu-size", xpath);
	data = yang_data_new_uint32(xpath_arg, pdu_size);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:if-state-change
 */
void isis_notif_if_state_change(const struct isis_circuit *circuit, bool down)
{
	const char *xpath = "/frr-isisd:if-state-change";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/state", xpath);
	data = yang_data_new_enum(xpath_arg, !!down);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:corrupted-lsp-detected
 */
void isis_notif_corrupted_lsp(const struct isis_area *area, const char *lsp_id)
{
	const char *xpath = "/frr-isisd:corrupted-lsp-detected";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:attempt-to-exceed-max-sequence
 */
void isis_notif_lsp_exceed_max(const struct isis_area *area, const char *lsp_id)
{
	const char *xpath = "/frr-isisd:attempt-to-exceed-max-sequence";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:max-area-addresses-mismatch
 */
void isis_notif_max_area_addr_mismatch(const struct isis_circuit *circuit,
				       uint8_t max_area_addrs,
				       const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:max-area-addresses-mismatch";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/max-area-addresses", xpath);
	data = yang_data_new_uint8(xpath_arg, max_area_addrs);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:authentication-type-failure
 */
void isis_notif_authentication_type_failure(const struct isis_circuit *circuit,
					    const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:authentication-type-failure";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:authentication-failure
 */
void isis_notif_authentication_failure(const struct isis_circuit *circuit,
				       const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:authentication-failure";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:adjacency-state-change
 */
void isis_notif_adj_state_change(const struct isis_adjacency *adj,
				 int new_state, const char *reason)
{
	const char *xpath = "/frr-isisd:adjacency-state-change";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_circuit *circuit = adj->circuit;
	struct isis_area *area = circuit->area;
	struct isis_dynhn *dyn = dynhn_find_by_id(adj->sysid);

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	if (dyn) {
		snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor", xpath);
		data = yang_data_new_string(xpath_arg, dyn->hostname);
		listnode_add(arguments, data);
	}
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-system-id", xpath);
	data = yang_data_new_string(xpath_arg, sysid_print(adj->sysid));
	listnode_add(arguments, data);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/state", xpath);
	data = yang_data_new_string(xpath_arg, isis_adj_yang_state(new_state));
	listnode_add(arguments, data);
	if (new_state == ISIS_ADJ_DOWN) {
		snprintf(xpath_arg, sizeof(xpath_arg), "%s/reason", xpath);
		data = yang_data_new_string(xpath_arg, reason);
		listnode_add(arguments, data);
	}

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:rejected-adjacency
 */
void isis_notif_reject_adjacency(const struct isis_circuit *circuit,
				 const char *reason, const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:rejected-adjacency";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/reason", xpath);
	data = yang_data_new_string(xpath_arg, reason);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:area-mismatch
 */
void isis_notif_area_mismatch(const struct isis_circuit *circuit,
			      const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:area-mismatch";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:lsp-received
 */
void isis_notif_lsp_received(const struct isis_circuit *circuit,
			     const char *lsp_id, uint32_t seqno,
			     uint32_t timestamp, const char *sys_id)
{
	const char *xpath = "/frr-isisd:lsp-received";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/sequence", xpath);
	data = yang_data_new_uint32(xpath_arg, seqno);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/received-timestamp", xpath);
	data = yang_data_new_uint32(xpath_arg, timestamp);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-system-id", xpath);
	data = yang_data_new_string(xpath_arg, sys_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:lsp-generation
 */
void isis_notif_lsp_gen(const struct isis_area *area, const char *lsp_id,
			uint32_t seqno, uint32_t timestamp)
{
	const char *xpath = "/frr-isisd:lsp-generation";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/sequence", xpath);
	data = yang_data_new_uint32(xpath_arg, seqno);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/send-timestamp", xpath);
	data = yang_data_new_uint32(xpath_arg, timestamp);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:id-len-mismatch
 */
void isis_notif_id_len_mismatch(const struct isis_circuit *circuit,
				uint8_t rcv_id_len, const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:id-len-mismatch";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/pdu-field-len", xpath);
	data = yang_data_new_uint8(xpath_arg, rcv_id_len);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:version-skew
 */
void isis_notif_version_skew(const struct isis_circuit *circuit,
			     uint8_t version, const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:version-skew";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/protocol-version", xpath);
	data = yang_data_new_uint8(xpath_arg, version);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:lsp-error-detected
 */
void isis_notif_lsp_error(const struct isis_circuit *circuit,
			  const char *lsp_id, const char *raw_pdu,
			  __attribute__((unused)) uint32_t offset,
			  __attribute__((unused)) uint8_t tlv_type)
{
	const char *xpath = "/frr-isisd:lsp-error-detected";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);
	/* ignore offset and tlv_type which cannot be set properly */

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:sequence-number-skipped
 */
void isis_notif_seqno_skipped(const struct isis_circuit *circuit,
			      const char *lsp_id)
{
	const char *xpath = "/frr-isisd:sequence-number-skipped";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-isisd:own-lsp-purge
 */
void isis_notif_own_lsp_purge(const struct isis_circuit *circuit,
			      const char *lsp_id)
{
	const char *xpath = "/frr-isisd:own-lsp-purge";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}
