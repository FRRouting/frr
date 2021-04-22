/**
 * bfd.h: BFD definitions and structures
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_BFD_H
#define _ZEBRA_BFD_H

#include "lib/json.h"
#include "lib/zclient.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BFD_DEF_MIN_RX 300
#define BFD_MIN_MIN_RX 50
#define BFD_MAX_MIN_RX 60000
#define BFD_DEF_MIN_TX 300
#define BFD_MIN_MIN_TX 50
#define BFD_MAX_MIN_TX 60000
#define BFD_DEF_DETECT_MULT 3
#define BFD_MIN_DETECT_MULT 2
#define BFD_MAX_DETECT_MULT 255

#define BFD_GBL_FLAG_IN_SHUTDOWN (1 << 0) /* The daemon in shutdown */
struct bfd_gbl {
	uint16_t flags;
};

#define BFD_FLAG_PARAM_CFG (1 << 0) /* parameters have been configured */
#define BFD_FLAG_BFD_REG   (1 << 1) /* Peer registered with BFD */
#define BFD_FLAG_BFD_TYPE_MULTIHOP (1 << 2) /* Peer registered with BFD as multihop */
#define BFD_FLAG_BFD_CBIT_ON (1 << 3) /* Peer registered with CBIT set to on */
#define BFD_FLAG_BFD_CHECK_CONTROLPLANE (1 << 4) /* BFD and controlplane daemon are linked */

#define BFD_STATUS_UNKNOWN    (1 << 0) /* BFD session status never received */
#define BFD_STATUS_DOWN       (1 << 1) /* BFD session status is down */
#define BFD_STATUS_UP         (1 << 2) /* BFD session status is up */
#define BFD_STATUS_ADMIN_DOWN (1 << 3) /* BFD session is admin down */

#define BFD_PROFILE_NAME_LEN 64

#define BFD_SET_CLIENT_STATUS(current_status, new_status)		  \
	do {								  \
		(current_status) =					  \
			(((new_status) == BFD_STATUS_ADMIN_DOWN) ?	  \
					  BFD_STATUS_DOWN : (new_status));\
	} while (0)

enum bfd_sess_type {
	BFD_TYPE_NOT_CONFIGURED,
	BFD_TYPE_SINGLEHOP,
	BFD_TYPE_MULTIHOP
};

struct bfd_info {
	uint16_t flags;
	uint8_t detect_mult;
	uint32_t desired_min_tx;
	uint32_t required_min_rx;
	time_t last_update;
	uint8_t status;
	enum bfd_sess_type type;
	char profile[BFD_PROFILE_NAME_LEN];
};

extern struct bfd_info *bfd_info_create(void);

extern void bfd_info_free(struct bfd_info **bfd_info);

extern int bfd_validate_param(struct vty *vty, const char *dm_str,
			      const char *rx_str, const char *tx_str,
			      uint8_t *dm_val, uint32_t *rx_val,
			      uint32_t *tx_val);

extern void bfd_set_param(struct bfd_info **bfd_info, uint32_t min_rx,
			  uint32_t min_tx, uint8_t detect_mult,
			  const char *profile, int defaults, int *command);
extern void bfd_peer_sendmsg(struct zclient *zclient, struct bfd_info *bfd_info,
			     int family, void *dst_ip, void *src_ip,
			     char *if_name, int ttl, int multihop, int cbit,
			     int command, int set_flag, vrf_id_t vrf_id);

extern const char *bfd_get_command_dbg_str(int command);

extern struct interface *bfd_get_peer_info(struct stream *s, struct prefix *dp,
					   struct prefix *sp, int *status,
					   int *remote_cbit,
					   vrf_id_t vrf_id);

const char *bfd_get_status_str(int status);

extern void bfd_show_param(struct vty *vty, struct bfd_info *bfd_info,
			   int bfd_tag, int extra_space, bool use_json,
			   json_object *json_obj);

extern void bfd_show_info(struct vty *vty, struct bfd_info *bfd_info,
			  int multihop, int extra_space, bool use_json,
			  json_object *json_obj);

extern void bfd_client_sendmsg(struct zclient *zclient, int command,
			       vrf_id_t vrf_id);

extern void bfd_gbl_init(void);

extern void bfd_gbl_exit(void);


/*
 * BFD new API.
 */

/* Forward declaration of argument struct. */
struct bfd_session_params;

/** Session state definitions. */
enum bfd_session_state {
	/** Session state is unknown or not initialized. */
	BSS_UNKNOWN = BFD_STATUS_UNKNOWN,
	/** Local or remote peer administratively shutdown the session. */
	BSS_ADMIN_DOWN = BFD_STATUS_ADMIN_DOWN,
	/** Session is down. */
	BSS_DOWN = BFD_STATUS_DOWN,
	/** Session is up and working correctly. */
	BSS_UP = BFD_STATUS_UP,
};

/** BFD session status information */
struct bfd_session_status {
	/** Current session state. */
	enum bfd_session_state state;
	/** Previous session state. */
	enum bfd_session_state previous_state;
	/** Remote Control Plane Independent bit state. */
	bool remote_cbit;
	/** Last event occurrence. */
	time_t last_event;
};

/**
 * Session status update callback.
 *
 * \param bsp BFD session parameters.
 * \param bss BFD session status.
 * \param arg application independent data.
 */
typedef void (*bsp_status_update)(struct bfd_session_params *bsp,
				  const struct bfd_session_status *bss,
				  void *arg);

/**
 * Allocates and initializes the session parameters.
 *
 * \param updatedb status update notification callback.
 * \param args application independent data.
 *
 * \returns pointer to configuration storage.
 */
struct bfd_session_params *bfd_sess_new(bsp_status_update updatecb, void *args);

/**
 * Uninstall session if installed and free resources allocated by the
 * parameters. Already sets pointer to `NULL` to avoid dangling references.
 *
 * \param bsp session parameters.
 */
void bfd_sess_free(struct bfd_session_params **bsp);

/**
 * Set the local and peer address of the BFD session.
 *
 * \param bsp BFD session parameters.
 * \param src local address (optional, can be `NULL`).
 * \param dst remote address (mandatory).
 */
void bfd_sess_set_ipv4_addrs(struct bfd_session_params *bsp,
			     struct in_addr *src, struct in_addr *dst);

/**
 * Set the local and peer address of the BFD session.
 *
 * \param bsp BFD session parameters.
 * \param src local address (optional, can be `NULL`).
 * \param dst remote address (mandatory).
 */
void bfd_sess_set_ipv6_addrs(struct bfd_session_params *bsp,
			     struct in6_addr *src, struct in6_addr *dst);

/**
 * Configure the BFD session interface.
 *
 * \param bsp BFD session parameters.
 * \param ifname interface name (or `NULL` to remove it).
 */
void bfd_sess_set_interface(struct bfd_session_params *bsp, const char *ifname);

/**
 * Configure the BFD session profile name.
 *
 * \param bsp BFD session parameters.
 * \param profile profile name (or `NULL` to remove it).
 */
void bfd_sess_set_profile(struct bfd_session_params *bsp, const char *profile);

/**
 * Configure the BFD session VRF.
 *
 * \param bsp BFD session parameters.
 * \param vrf_id the VRF identification number.
 */
void bfd_sess_set_vrf(struct bfd_session_params *bsp, vrf_id_t vrf_id);

/**
 * Configure the BFD session single/multi hop setting.
 *
 * \param bsp BFD session parameters.
 * \param min_ttl minimum TTL value expected (255 for single hop, 254 for
 *                multi hop with single hop, 253 for multi hop with two hops
 *                and so on). See `BFD_SINGLE_HOP_TTL` and
 *                `BFD_MULTI_HOP_MIN_TTL` for defaults.
 *
 * To simplify things if your protocol only knows the amount of hops it is
 * better to use `bfd_sess_set_hops` instead.
 */
void bfd_sess_set_mininum_ttl(struct bfd_session_params *bsp, uint8_t min_ttl);

/** To use single hop the minimum TTL must be set to this. */
#define BFD_SINGLE_HOP_TTL 255
/** To use multi hop the minimum TTL must be set to this or less. */
#define BFD_MULTI_HOP_MIN_TTL 254

/**
 * This function is the inverted version of `bfd_sess_set_minimum_ttl`.
 * Instead of receiving the minimum expected TTL, it receives the amount of
 * hops the protocol will jump.
 *
 * \param bsp BFD session parameters.
 * \param min_ttl minimum amount of hops expected (1 for single hop, 2 or
 *                more for multi hop).
 */
void bfd_sess_set_hop_count(struct bfd_session_params *bsp, uint8_t min_ttl);

/**
 * Configure the BFD session to set the Control Plane Independent bit.
 *
 * \param bsp BFD session parameters.
 * \param enable BFD Control Plane Independent state.
 */
void bfd_sess_set_cbit(struct bfd_session_params *bsp, bool enable);

/**
 * DEPRECATED: please avoid using timers directly and use profiles instead.
 *
 * Configures the BFD session timers to use. This is specially useful with
 * `ptm-bfd` which does not support timers.
 *
 * \param bsp BFD session parameters.
 * \param detection_multiplier the detection multiplier value.
 * \param min_rx minimum required receive period.
 * \param min_tx minimum required transmission period.
 */
void bfd_sess_set_timers(struct bfd_session_params *bsp,
			 uint8_t detection_multiplier, uint32_t min_rx,
			 uint32_t min_tx);

/**
 * Installs or updates the BFD session based on the saved session arguments.
 *
 * \param bsp session parameters.
 */
void bfd_sess_install(struct bfd_session_params *bsp);

/**
 * Uninstall the BFD session based on the saved session arguments.
 *
 * \param bsp session parameters.
 */
void bfd_sess_uninstall(struct bfd_session_params *bsp);

/**
 * Get BFD session current status.
 *
 * \param bsp session parameters.
 *
 * \returns BFD session status data structure.
 */
enum bfd_session_state bfd_sess_status(const struct bfd_session_params *bsp);

/**
 * Get BFD session minimum TTL configured value.
 *
 * \param bsp session parameters.
 *
 * \returns configured minimum TTL.
 */
uint8_t bfd_sess_minimum_ttl(const struct bfd_session_params *bsp);

/**
 * Inverted version of `bfd_sess_minimum_ttl`. Gets the amount of hops in the
 * way to the peer.
 *
 * \param bsp session parameters.
 *
 * \returns configured amount of hops.
 */
uint8_t bfd_sess_hop_count(const struct bfd_session_params *bsp);

/**
 * Get BFD session profile configured value.
 *
 * \param bsp session parameters.
 *
 * \returns configured profile name (or `NULL` if empty).
 */
const char *bfd_sess_profile(const struct bfd_session_params *bsp);

/**
 * Get BFD session addresses.
 *
 * \param bsp session parameters.
 * \param family the address family being used (AF_INET or AF_INET6).
 * \param src source address (optional, may be `NULL`).
 * \param dst peer address (optional, may be `NULL`).
 */
void bfd_sess_addresses(const struct bfd_session_params *bsp, int *family,
			struct in6_addr *src, struct in6_addr *dst);
/**
 * Get BFD session interface name.
 *
 * \param bsp session parameters.
 *
 * \returns `NULL` if not set otherwise the interface name.
 */
const char *bfd_sess_interface(const struct bfd_session_params *bsp);

/**
 * Get BFD session VRF name.
 *
 * \param bsp session parameters.
 *
 * \returns the VRF name.
 */
const char *bfd_sess_vrf(const struct bfd_session_params *bsp);

/**
 * Get BFD session VRF ID.
 *
 * \param bsp session parameters.
 *
 * \returns the VRF name.
 */
vrf_id_t bfd_sess_vrf_id(const struct bfd_session_params *bsp);

/**
 * Get BFD session control plane independent bit configuration state.
 *
 * \param bsp session parameters.
 *
 * \returns `true` if enabled otherwise `false`.
 */
bool bfd_sess_cbit(const struct bfd_session_params *bsp);

/**
 * DEPRECATED: please avoid using timers directly and use profiles instead.
 *
 * Gets the configured timers.
 *
 * \param bsp BFD session parameters.
 * \param detection_multiplier the detection multiplier value.
 * \param min_rx minimum required receive period.
 * \param min_tx minimum required transmission period.
 */
void bfd_sess_timers(const struct bfd_session_params *bsp,
		     uint8_t *detection_multiplier, uint32_t *min_rx,
		     uint32_t *min_tx);

/**
 * Show BFD session configuration and status. If `json` is provided (e.g. not
 * `NULL`) then information will be inserted in object, otherwise printed to
 * `vty`.
 *
 * \param vty Pointer to `vty` for outputting text.
 * \param json (optional) JSON object pointer.
 * \param bsp session parameters.
 */
void bfd_sess_show(struct vty *vty, struct json_object *json,
		   struct bfd_session_params *bsp);

/**
 * Initializes the BFD integration library. This function executes the
 * following actions:
 *
 * - Copy the `struct thread_master` pointer to use as "thread" to execute
 *   the BFD session parameters installation.
 * - Copy the `struct zclient` pointer to install its callbacks.
 * - Initializes internal data structures.
 *
 * \param tm normally the daemon main thread event manager.
 * \param zc the zebra client of the daemon.
 */
void bfd_protocol_integration_init(struct zclient *zc,
				   struct thread_master *tm);

/**
 * BFD session registration arguments.
 */
struct bfd_session_arg {
	/**
	 * BFD command.
	 *
	 * Valid commands:
	 * - `ZEBRA_BFD_DEST_REGISTER`
	 * - `ZEBRA_BFD_DEST_DEREGISTER`
	 */
	int32_t command;

	/**
	 * BFD family type.
	 *
	 * Supported types:
	 * - `AF_INET`
	 * - `AF_INET6`.
	 */
	uint32_t family;
	/** Source address. */
	struct in6_addr src;
	/** Source address. */
	struct in6_addr dst;

	/** Multi hop indicator. */
	uint8_t mhop;
	/** Expected TTL. */
	uint8_t ttl;
	/** C bit (Control Plane Independent bit) indicator. */
	uint8_t cbit;

	/** Interface name size. */
	uint8_t ifnamelen;
	/** Interface name. */
	char ifname[64];

	/** Daemon or session VRF. */
	vrf_id_t vrf_id;

	/** Profile name length. */
	uint8_t profilelen;
	/** Profile name. */
	char profile[BFD_PROFILE_NAME_LEN];

	/*
	 * Deprecation fields: these fields should be removed once `ptm-bfd`
	 * no longer uses this interface.
	 */

	/** Minimum required receive interval (in microseconds). */
	uint32_t min_rx;
	/** Minimum desired transmission interval (in microseconds). */
	uint32_t min_tx;
	/** Detection multiplier. */
	uint32_t detection_multiplier;

	/** BFD client information output. */
	struct bfd_info *bfd_info;

	/** Write registration indicator. */
	uint8_t set_flag;
};

/**
 * Send a message to BFD daemon through the zebra client.
 *
 * \param zc the zebra client context.
 * \param arg the BFD session command arguments.
 *
 * \returns `-1` on failure otherwise `0`.
 *
 * \see bfd_session_arg.
 */
extern int zclient_bfd_command(struct zclient *zc, struct bfd_session_arg *arg);

/**
 * Enables or disables BFD protocol integration API debugging.
 *
 * \param enable new API debug state.
 */
extern void bfd_protocol_integration_set_debug(bool enable);

/**
 * Sets shutdown mode so no more events are processed.
 *
 * This is useful to avoid the event storm that happens caused by network,
 * interfaces or VRFs removal. It should also avoid some crashes due hanging
 * pointers left overs by protocol.
 *
 * \param enable new API shutdown state.
 */
extern void bfd_protocol_integration_set_shutdown(bool enable);

/**
 * Get API debugging state.
 */
extern bool bfd_protocol_integration_debug(void);

/**
 * Get API shutdown state.
 */
extern bool bfd_protocol_integration_shutting_down(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_BFD_H */
