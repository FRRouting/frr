// SPDX-License-Identifier: GPL-2.0-or-later
/* Declarations and definitions for kernel interaction over netlink
 * Copyright (C) 2016 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_KERNEL_NETLINK_H
#define _ZEBRA_KERNEL_NETLINK_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_NETLINK

#define RTM_NHA(h)                                                             \
	((struct rtattr *)(((char *)(h)) + NLMSG_ALIGN(sizeof(struct nhmsg))))


#define NL_RCV_PKT_BUF_SIZE     (34 * 1024)
#define NL_PKT_BUF_SIZE         8192

/*
 * nl_attr_put - add an attribute to the Netlink message.
 *
 * Returns true if the attribute could be added to the message (fits into the
 * buffer), otherwise false is returned.
 */
extern bool nl_attr_put(struct nlmsghdr *n, unsigned int maxlen, int type,
			const void *data, unsigned int alen);
extern bool nl_attr_put8(struct nlmsghdr *n, unsigned int maxlen, int type,
			 uint8_t data);
extern bool nl_attr_put16(struct nlmsghdr *n, unsigned int maxlen, int type,
			  uint16_t data);
extern bool nl_attr_put32(struct nlmsghdr *n, unsigned int maxlen, int type,
			  uint32_t data);
extern bool nl_attr_put64(struct nlmsghdr *n, unsigned int maxlen, int type,
			  uint64_t data);

/*
 * nl_attr_nest - start an attribute nest.
 *
 * Returns a valid pointer to the beginning of the nest if the attribute
 * describing the nest could be added to the message (fits into the buffer),
 * otherwise NULL is returned.
 */
extern struct rtattr *nl_attr_nest(struct nlmsghdr *n, unsigned int maxlen,
				   int type);

/*
 * nl_attr_nest_end - finalize nesting of attributes.
 *
 * Updates the length field of the attribute header to include the appeneded
 * attributes. Returns a total length of the Netlink message.
 */
extern int nl_attr_nest_end(struct nlmsghdr *n, struct rtattr *nest);

/*
 * nl_attr_rtnh - append a rtnexthop record to the Netlink message.
 *
 * Returns a valid pointer to the rtnexthop struct if it could be added to
 * the message (fits into the buffer), otherwise NULL is returned.
 */
extern struct rtnexthop *nl_attr_rtnh(struct nlmsghdr *n, unsigned int maxlen);

/*
 * nl_attr_rtnh_end - finalize adding a rtnexthop record.
 *
 * Updates the length field of the rtnexthop to include the appeneded
 * attributes.
 */
extern void nl_attr_rtnh_end(struct nlmsghdr *n, struct rtnexthop *rtnh);

extern void netlink_parse_rtattr(struct rtattr **tb, int max,
				 struct rtattr *rta, int len);
extern void netlink_parse_rtattr_flags(struct rtattr **tb, int max,
				 struct rtattr *rta, int len,
				 unsigned short flags);
extern void netlink_parse_rtattr_nested(struct rtattr **tb, int max,
					struct rtattr *rta);
/*
 * nl_addraw_l copies raw form the netlink message buffer into netlink
 * message header pointer. It ensures the aligned data buffer does not
 * override past max length.
 * return value is 0 if its successful
 */
extern bool nl_addraw_l(struct nlmsghdr *n, unsigned int maxlen,
			const void *data, unsigned int len);
extern const char *nl_msg_type_to_str(uint16_t msg_type);
extern const char *nl_rtproto_to_str(uint8_t rtproto);
extern const char *nl_family_to_str(uint8_t family);
extern const char *nl_rttype_to_str(uint8_t rttype);

extern int netlink_parse_info(int (*filter)(struct nlmsghdr *, ns_id_t, int),
			      struct nlsock *nl,
			      const struct zebra_dplane_info *dp_info,
			      int count, bool startup);
extern int netlink_talk_filter(struct nlmsghdr *h, ns_id_t ns, int startup);
extern int netlink_talk(int (*filter)(struct nlmsghdr *, ns_id_t, int startup),
			struct nlmsghdr *n, struct nlsock *nl,
			struct zebra_ns *zns, bool startup);
extern int netlink_request(struct nlsock *nl, void *req);

enum netlink_msg_status {
	FRR_NETLINK_SUCCESS,
	FRR_NETLINK_ERROR,
	FRR_NETLINK_QUEUED,
};

struct nl_batch;

/*
 * netlink_batch_add_msg - add message to the netlink batch using dplane
 * context object.
 *
 * @ctx:         Dataplane context
 * @msg_encoder: A function that encodes dplane context object into
 *               netlink message. Should take dplane context object,
 *               pointer to a buffer and buffer's length as parameters
 *               and should return -1 on error, 0 on buffer overflow or
 *               size of the encoded message.
 * @ignore_res:  Whether the result of this message should be ignored.
 *               This should be used in some 'update' cases where we
 *               need to send two messages for one context object.
 *
 * Return:		Status of the message.
 */
extern enum netlink_msg_status netlink_batch_add_msg(
	struct nl_batch *bth, struct zebra_dplane_ctx *ctx,
	ssize_t (*msg_encoder)(struct zebra_dplane_ctx *, void *, size_t),
	bool ignore_res);

/*
 * Vty/cli apis
 */
extern int netlink_config_write_helper(struct vty *vty);

/*
 * Configure size of the batch buffer and sending threshold. If 'unset', reset
 * to default value.
 */
extern void netlink_set_batch_buffer_size(uint32_t size, uint32_t threshold,
					  bool set);

extern struct nlsock *kernel_netlink_nlsock_lookup(int sock);
#endif /* HAVE_NETLINK */

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_KERNEL_NETLINK_H */
