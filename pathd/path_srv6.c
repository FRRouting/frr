// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2025 6WIND S.A.
 */

#include "zebra.h"
#include "memory.h"
#include "srv6.h"
#include "pathd.h"

DEFINE_MTYPE_STATIC(PATHD, PATH_SRV6_ENCAP, "SRv6 Encapsulation Type");

static char *srv6_encap_behavior_segment_list_str;
static enum srv6_headend_behavior srv6_encap_behavior_segment_list;

void path_srv6_init(void)
{
	srv6_use_sid_manager = false;
	srv6_encap_behavior_segment_list_str = XSTRDUP(MTYPE_PATH_SRV6_ENCAP,
						       "ietf-srv6-types:H.Encaps");
	srv6_encap_behavior_segment_list = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
}

void path_srv6_destroy(void)
{
	XFREE(MTYPE_PATH_SRV6_ENCAP, srv6_encap_behavior_segment_list_str);
}

enum srv6_headend_behavior path_srv6_get_encap_type_segment_list(void)
{
	return srv6_encap_behavior_segment_list;
}

void path_srv6_set_encap_type_segment_list_str(const char *srv6_encap_behavior_str)
{
	if (srv6_encap_behavior_segment_list_str)
		XFREE(MTYPE_PATH_SRV6_ENCAP, srv6_encap_behavior_segment_list_str);
	srv6_encap_behavior_segment_list_str = XSTRDUP(MTYPE_PATH_SRV6_ENCAP,
						       srv6_encap_behavior_str);
	if (strmatch(srv6_encap_behavior_segment_list_str, "ietf-srv6-types:H.Encaps.Red"))
		srv6_encap_behavior_segment_list = SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED;
	else if (strmatch(srv6_encap_behavior_segment_list_str, "ietf-srv6-types:H.Encaps"))
		srv6_encap_behavior_segment_list = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
}

void path_srv6_show_running(struct vty *vty)
{
	if (srv6_use_sid_manager)
		vty_out(vty, "  use-srv6-sid-manager\n");
	if (srv6_encap_behavior_segment_list_str == NULL)
		return;
	if (strmatch(srv6_encap_behavior_segment_list_str, "ietf-srv6-types:H.Encaps.Red"))
		vty_out(vty, "  srv6-encap-behavior segment-list %s\n",
			srv6_headend_behavior2str(srv6_encap_behavior_segment_list, true));
}
