// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * bfd.h: BFD definitions and structures
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_BFD_H
#define _ZEBRA_BFD_H

#include "lib/json.h"
#include "lib/zclient.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BFD_DEF_MIN_RX 300
#define BFD_DEF_MIN_TX 300
#define BFD_DEF_DETECT_MULT 3

#define BFD_STATUS_UNKNOWN    (1 << 0) /* BFD session status never received */
#define BFD_STATUS_DOWN       (1 << 1) /* BFD session status is down */
#define BFD_STATUS_UP         (1 << 2) /* BFD session status is up */
#define BFD_STATUS_ADMIN_DOWN (1 << 3) /* BFD session is admin down */

#define BFD_PROFILE_NAME_LEN 64

const char *bfd_get_status_str(int status);

extern void bfd_client_sendmsg(struct zclient *zclient, int command,
			       vrf_id_t vrf_id);

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
 * \param updatecb status update notification callback.
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
 * NOTE:
 * If the address changed the session is removed and must be installed again
 * with `bfd_sess_install`.
 *
 * \param bsp BFD session parameters.
 * \param src local address (optional, can be `NULL`).
 * \param dst remote address (mandatory).
 */
void bfd_sess_set_ipv4_addrs(struct bfd_session_params *bsp,
			     const struct in_addr *src,
			     const struct in_addr *dst);

/**
 * Set the local and peer address of the BFD session.
 *
 * NOTE:
 * If the address changed the session is removed and must be installed again
 * with `bfd_sess_install`.
 *
 * \param bsp BFD session parameters.
 * \param src local address (optional, can be `NULL`).
 * \param dst remote address (mandatory).
 */
void bfd_sess_set_ipv6_addrs(struct bfd_session_params *bsp,
			     const struct in6_addr *src,
			     const struct in6_addr *dst);

/**
 * Configure the BFD session interface.
 *
 * NOTE:
 * If the interface changed the session is removed and must be installed again
 * with `bfd_sess_install`.
 *
 * \param bsp BFD session parameters.
 * \param ifname interface name (or `NULL` to remove it).
 */
void bfd_sess_set_interface(struct bfd_session_params *bsp, const char *ifname);

/**
 * Configure the BFD session profile name.
 *
 * NOTE:
 * Session profile will only change after a `bfd_sess_install`.
 *
 * \param bsp BFD session parameters.
 * \param profile profile name (or `NULL` to remove it).
 */
void bfd_sess_set_profile(struct bfd_session_params *bsp, const char *profile);

/**
 * Configure the BFD session VRF.
 *
 * NOTE:
 * If the VRF changed the session is removed and must be installed again
 * with `bfd_sess_install`.
 *
 * \param bsp BFD session parameters.
 * \param vrf_id the VRF identification number.
 */
void bfd_sess_set_vrf(struct bfd_session_params *bsp, vrf_id_t vrf_id);

/**
 * Configure the BFD session single/multi hop setting.
 *
 * NOTE:
 * If the number of hops is changed the session is removed and must be
 * installed again with `bfd_sess_install`.
 *
 * \param bsp BFD session parameters.
 * \param hops maximum amount of hops expected (1 for single hop, 2 or
 *             more for multi hop).
 */
void bfd_sess_set_hop_count(struct bfd_session_params *bsp, uint8_t hops);

/**
 * Configure the BFD session to set the Control Plane Independent bit.
 *
 * NOTE:
 * Session CPI bit will only change after a `bfd_sess_install`.
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
 * NOTE:
 * Session timers will only apply if the session has not been created yet.
 * If the session is already installed you must uninstall and install again
 * to take effect.
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
 * Configures the automatic source selection for the BFD session.
 *
 * NOTE:
 * Setting this configuration will override the IP source value set by
 * `bfd_sess_set_ipv4_addrs` or `bfd_sess_set_ipv6_addrs`.
 *
 * \param bsp BFD session parameters
 * \param enable BFD automatic source selection state.
 */
void bfd_sess_set_auto_source(struct bfd_session_params *bsp, bool enable);

/**
 * Installs or updates the BFD session based on the saved session arguments.
 *
 * NOTE:
 * This function has a delayed effect: it will only install/update after
 * all northbound/CLI command batch finishes.
 *
 * \param bsp session parameters.
 */
void bfd_sess_install(struct bfd_session_params *bsp);

/**
 * Uninstall the BFD session based on the saved session arguments.
 *
 * NOTE:
 * This function uninstalls the session immediately (if installed) and cancels
 * any previous `bfd_sess_install` calls.
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
 * Get BFD session amount of hops configured value.
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
 * Gets the automatic source selection state.
 */
bool bfd_sess_auto_source(const struct bfd_session_params *bsp);

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
 * - Copy the `struct event_loop` pointer to use as "thread" to execute
 *   the BFD session parameters installation.
 * - Copy the `struct zclient` pointer to install its callbacks.
 * - Initializes internal data structures.
 *
 * \param tm normally the daemon main thread event manager.
 * \param zc the zebra client of the daemon.
 */
void bfd_protocol_integration_init(struct zclient *zc, struct event_loop *tm);

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
	/** Expected hops. */
	uint8_t hops;
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

/* Update nexthop-tracking (nht) information for BFD auto source selection.
 * The function must be called from the daemon callback function
 * that deals with the ZEBRA_NEXTHOP_UPDATE zclient command
 */
extern int bfd_nht_update(const struct prefix *match,
			  const struct zapi_route *route);

extern bool bfd_session_is_down(const struct bfd_session_params *session);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_BFD_H */
