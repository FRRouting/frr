// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#ifndef _FRR_NORTHBOUND_WRAPPERS_H_
#define _FRR_NORTHBOUND_WRAPPERS_H_

#include "prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

/* bool */
extern bool yang_str2bool(const char *value);
extern struct yang_data *yang_data_new_bool(const char *xpath, bool value);
extern bool yang_dnode_get_bool(const struct lyd_node *dnode,
				const char *xpath_fmt, ...) PRINTFRR(2, 3);
extern bool yang_get_default_bool(const char *xpath_fmt, ...) PRINTFRR(1, 2);

/* dec64 */
extern double yang_str2dec64(const char *xpath, const char *value);
extern struct yang_data *yang_data_new_dec64(const char *xpath, double value);
extern double yang_dnode_get_dec64(const struct lyd_node *dnode,
				   const char *xpath_fmt, ...) PRINTFRR(2, 3);
extern double yang_get_default_dec64(const char *xpath_fmt, ...) PRINTFRR(1, 2);

/* enum */
extern int yang_str2enum(const char *xpath, const char *value);
extern struct yang_data *yang_data_new_enum(const char *xpath, int value);
extern int yang_dnode_get_enum(const struct lyd_node *dnode,
			       const char *xpath_fmt, ...) PRINTFRR(2, 3);
extern int yang_get_default_enum(const char *xpath_fmt, ...) PRINTFRR(1, 2);

/* int8 */
extern int8_t yang_str2int8(const char *value);
extern struct yang_data *yang_data_new_int8(const char *xpath, int8_t value);
extern int8_t yang_dnode_get_int8(const struct lyd_node *dnode,
				  const char *xpath_fmt, ...) PRINTFRR(2, 3);
extern int8_t yang_get_default_int8(const char *xpath_fmt, ...) PRINTFRR(1, 2);

/* int16 */
extern int16_t yang_str2int16(const char *value);
extern struct yang_data *yang_data_new_int16(const char *xpath, int16_t value);
extern int16_t yang_dnode_get_int16(const struct lyd_node *dnode,
				    const char *xpath_fmt, ...) PRINTFRR(2, 3);
extern int16_t yang_get_default_int16(const char *xpath_fmt, ...)
	PRINTFRR(1, 2);

/* int32 */
extern int32_t yang_str2int32(const char *value);
extern struct yang_data *yang_data_new_int32(const char *xpath, int32_t value);
extern int32_t yang_dnode_get_int32(const struct lyd_node *dnode,
				    const char *xpath_fmt, ...) PRINTFRR(2, 3);
extern int32_t yang_get_default_int32(const char *xpath_fmt, ...)
	PRINTFRR(1, 2);

/* int64 */
extern int64_t yang_str2int64(const char *value);
extern struct yang_data *yang_data_new_int64(const char *xpath, int64_t value);
extern int64_t yang_dnode_get_int64(const struct lyd_node *dnode,
				    const char *xpath_fmt, ...) PRINTFRR(2, 3);
extern int64_t yang_get_default_int64(const char *xpath_fmt, ...)
	PRINTFRR(1, 2);

/* uint8 */
extern uint8_t yang_str2uint8(const char *value);
extern struct yang_data *yang_data_new_uint8(const char *xpath, uint8_t value);
extern uint8_t yang_dnode_get_uint8(const struct lyd_node *dnode,
				    const char *xpath_fmt, ...) PRINTFRR(2, 3);
extern uint8_t yang_get_default_uint8(const char *xpath_fmt, ...)
	PRINTFRR(1, 2);

/* uint16 */
extern uint16_t yang_str2uint16(const char *value);
extern struct yang_data *yang_data_new_uint16(const char *xpath,
					      uint16_t value);
extern uint16_t yang_dnode_get_uint16(const struct lyd_node *dnode,
				      const char *xpath_fmt, ...)
	PRINTFRR(2, 3);
extern uint16_t yang_get_default_uint16(const char *xpath_fmt, ...)
	PRINTFRR(1, 2);

/* uint32 */
extern uint32_t yang_str2uint32(const char *value);
extern struct yang_data *yang_data_new_uint32(const char *xpath,
					      uint32_t value);
extern uint32_t yang_dnode_get_uint32(const struct lyd_node *dnode,
				      const char *xpath_fmt, ...)
	PRINTFRR(2, 3);
extern uint32_t yang_get_default_uint32(const char *xpath_fmt, ...)
	PRINTFRR(1, 2);

/* uint64 */
extern uint64_t yang_str2uint64(const char *value);
extern struct yang_data *yang_data_new_uint64(const char *xpath,
					      uint64_t value);
extern uint64_t yang_dnode_get_uint64(const struct lyd_node *dnode,
				      const char *xpath_fmt, ...)
	PRINTFRR(2, 3);
extern uint64_t yang_get_default_uint64(const char *xpath_fmt, ...)
	PRINTFRR(1, 2);

/* string */
extern struct yang_data *yang_data_new_string(const char *xpath,
					      const char *value);
extern const char *yang_dnode_get_string(const struct lyd_node *dnode,
					 const char *xpath_fmt, ...)
	PRINTFRR(2, 3);
extern void yang_dnode_get_string_buf(char *buf, size_t size,
				      const struct lyd_node *dnode,
				      const char *xpath_fmt, ...)
	PRINTFRR(4, 5);
extern const char *yang_get_default_string(const char *xpath_fmt, ...)
	PRINTFRR(1, 2);
extern void yang_get_default_string_buf(char *buf, size_t size,
					const char *xpath_fmt, ...)
	PRINTFRR(3, 4);

/* binary */
extern struct yang_data *yang_data_new_binary(const char *xpath,
					      const char *value, size_t len);
extern size_t yang_dnode_get_binary_buf(char *buf, size_t size,
					const struct lyd_node *dnode,
					const char *xpath_fmt, ...)
	PRINTFRR(4, 5);

/* empty */
extern struct yang_data *yang_data_new_empty(const char *xpath);
extern bool yang_dnode_get_empty(const struct lyd_node *dnode,
				 const char *xpath_fmt, ...) PRINTFRR(2, 3);

/* ip prefix */
extern void yang_str2prefix(const char *value, union prefixptr prefix);
extern struct yang_data *yang_data_new_prefix(const char *xpath,
					      union prefixconstptr prefix);
extern void yang_dnode_get_prefix(struct prefix *prefix,
				  const struct lyd_node *dnode,
				  const char *xpath_fmt, ...) PRINTFRR(3, 4);
extern void yang_get_default_prefix(union prefixptr var, const char *xpath_fmt,
				    ...) PRINTFRR(2, 3);

/* ipv4 */
extern void yang_str2ipv4(const char *value, struct in_addr *addr);
extern struct yang_data *yang_data_new_ipv4(const char *xpath,
					    const struct in_addr *addr);
extern void yang_dnode_get_ipv4(struct in_addr *addr,
				const struct lyd_node *dnode,
				const char *xpath_fmt, ...) PRINTFRR(3, 4);
extern void yang_get_default_ipv4(struct in_addr *var, const char *xpath_fmt,
				  ...) PRINTFRR(2, 3);

/* ipv4p */
extern void yang_str2ipv4p(const char *value, union prefixptr prefix);
extern struct yang_data *yang_data_new_ipv4p(const char *xpath,
					     union prefixconstptr prefix);
extern void yang_dnode_get_ipv4p(union prefixptr prefix,
				 const struct lyd_node *dnode,
				 const char *xpath_fmt, ...) PRINTFRR(3, 4);
extern void yang_get_default_ipv4p(union prefixptr var, const char *xpath_fmt,
				   ...) PRINTFRR(2, 3);

/* ipv6 */
extern void yang_str2ipv6(const char *value, struct in6_addr *addr);
extern struct yang_data *yang_data_new_ipv6(const char *xpath,
					    const struct in6_addr *addr);
extern void yang_dnode_get_ipv6(struct in6_addr *addr,
				const struct lyd_node *dnode,
				const char *xpath_fmt, ...) PRINTFRR(3, 4);
extern void yang_get_default_ipv6(struct in6_addr *var, const char *xpath_fmt,
				  ...) PRINTFRR(2, 3);

/* ipv6p */
extern void yang_str2ipv6p(const char *value, union prefixptr prefix);
extern struct yang_data *yang_data_new_ipv6p(const char *xpath,
					     union prefixconstptr prefix);
extern void yang_dnode_get_ipv6p(union prefixptr prefix,
				 const struct lyd_node *dnode,
				 const char *xpath_fmt, ...) PRINTFRR(3, 4);
extern void yang_get_default_ipv6p(union prefixptr var, const char *xpath_fmt,
				   ...) PRINTFRR(2, 3);

/* ip */
extern void yang_str2ip(const char *value, struct ipaddr *addr);
extern struct yang_data *yang_data_new_ip(const char *xpath,
					  const struct ipaddr *addr);
extern void yang_dnode_get_ip(struct ipaddr *addr, const struct lyd_node *dnode,
			      const char *xpath_fmt, ...) PRINTFRR(3, 4);
extern void yang_get_default_ip(struct ipaddr *var, const char *xpath_fmt, ...)
	PRINTFRR(2, 3);

/* mac */
extern struct yang_data *yang_data_new_mac(const char *xpath,
					   const struct ethaddr *mac);
extern void yang_str2mac(const char *value, struct ethaddr *mac);
extern void yang_dnode_get_mac(struct ethaddr *mac, const struct lyd_node *dnode,
			       const char *xpath_fmt, ...) PRINTFRR(3, 4);

/*data-and-time */
extern struct yang_data *yang_data_new_date_and_time(const char *xpath,
						     time_t time);

/* rt-types:bandwidth-ieee-float32 */
extern float yang_dnode_get_bandwidth_ieee_float32(const struct lyd_node *dnode,
						   const char *xpath_fmt, ...)
	PRINTFRR(2, 3);

/* nexthop enum2str */
extern const char *yang_nexthop_type2str(uint32_t ntype);

const char *yang_afi_safi_value2identity(afi_t afi, safi_t safi);
void yang_afi_safi_identity2value(const char *key, afi_t *afi, safi_t *safi);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_NORTHBOUND_WRAPPERS_H_ */
