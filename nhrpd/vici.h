<<<<<<< HEAD
=======
// SPDX-License-Identifier: GPL-2.0-or-later
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)

enum vici_type_t {
	VICI_START = 0,
	VICI_SECTION_START = 1,
	VICI_SECTION_END = 2,
	VICI_KEY_VALUE = 3,
	VICI_LIST_START = 4,
	VICI_LIST_ITEM = 5,
	VICI_LIST_END = 6,
	VICI_END = 7
};

enum vici_operation_t {
	VICI_CMD_REQUEST = 0,
	VICI_CMD_RESPONSE,
	VICI_CMD_UNKNOWN,
	VICI_EVENT_REGISTER,
	VICI_EVENT_UNREGISTER,
	VICI_EVENT_CONFIRM,
	VICI_EVENT_UNKNOWN,
	VICI_EVENT,
};

#define VICI_MAX_MSGLEN		(512*1024)
