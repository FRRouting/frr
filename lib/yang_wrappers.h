/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#ifndef _FRR_NORTHBOUND_WRAPPERS_H_
#define _FRR_NORTHBOUND_WRAPPERS_H_

#include "prefix.h"

/* bool */
extern bool yang_str2bool(const char *value);
extern struct yang_data *yang_data_new_bool(const char *xpath, bool value);
extern bool yang_dnode_get_bool(const struct lyd_node *dnode,
				const char *xpath_fmt, ...);
extern bool yang_get_default_bool(const char *xpath_fmt, ...);

/* dec64 */
extern double yang_str2dec64(const char *xpath, const char *value);
extern struct yang_data *yang_data_new_dec64(const char *xpath, double value);
extern double yang_dnode_get_dec64(const struct lyd_node *dnode,
				   const char *xpath_fmt, ...);
extern double yang_get_default_dec64(const char *xpath_fmt, ...);

/* enum */
extern int yang_str2enum(const char *xpath, const char *value);
extern struct yang_data *yang_data_new_enum(const char *xpath, int value);
extern int yang_dnode_get_enum(const struct lyd_node *dnode,
			       const char *xpath_fmt, ...);
extern int yang_get_default_enum(const char *xpath_fmt, ...);

/* int8 */
extern int8_t yang_str2int8(const char *value);
extern struct yang_data *yang_data_new_int8(const char *xpath, int8_t value);
extern int8_t yang_dnode_get_int8(const struct lyd_node *dnode,
				  const char *xpath_fmt, ...);
extern int8_t yang_get_default_int8(const char *xpath_fmt, ...);

/* int16 */
extern int16_t yang_str2int16(const char *value);
extern struct yang_data *yang_data_new_int16(const char *xpath, int16_t value);
extern int16_t yang_dnode_get_int16(const struct lyd_node *dnode,
				    const char *xpath_fmt, ...);
extern int16_t yang_get_default_int16(const char *xpath_fmt, ...);

/* int32 */
extern int32_t yang_str2int32(const char *value);
extern struct yang_data *yang_data_new_int32(const char *xpath, int32_t value);
extern int32_t yang_dnode_get_int32(const struct lyd_node *dnode,
				    const char *xpath_fmt, ...);
extern int32_t yang_get_default_int32(const char *xpath_fmt, ...);

/* int64 */
extern int64_t yang_str2int64(const char *value);
extern struct yang_data *yang_data_new_int64(const char *xpath, int64_t value);
extern int64_t yang_dnode_get_int64(const struct lyd_node *dnode,
				    const char *xpath_fmt, ...);
extern int64_t yang_get_default_int64(const char *xpath_fmt, ...);

/* uint8 */
extern uint8_t yang_str2uint8(const char *value);
extern struct yang_data *yang_data_new_uint8(const char *xpath, uint8_t value);
extern uint8_t yang_dnode_get_uint8(const struct lyd_node *dnode,
				    const char *xpath_fmt, ...);
extern uint8_t yang_get_default_uint8(const char *xpath_fmt, ...);

/* uint16 */
extern uint16_t yang_str2uint16(const char *value);
extern struct yang_data *yang_data_new_uint16(const char *xpath,
					      uint16_t value);
extern uint16_t yang_dnode_get_uint16(const struct lyd_node *dnode,
				      const char *xpath_fmt, ...);
extern uint16_t yang_get_default_uint16(const char *xpath_fmt, ...);

/* uint32 */
extern uint32_t yang_str2uint32(const char *value);
extern struct yang_data *yang_data_new_uint32(const char *xpath,
					      uint32_t value);
extern uint32_t yang_dnode_get_uint32(const struct lyd_node *dnode,
				      const char *xpath_fmt, ...);
extern uint32_t yang_get_default_uint32(const char *xpath_fmt, ...);

/* uint64 */
extern uint64_t yang_str2uint64(const char *value);
extern struct yang_data *yang_data_new_uint64(const char *xpath,
					      uint64_t value);
extern uint64_t yang_dnode_get_uint64(const struct lyd_node *dnode,
				      const char *xpath_fmt, ...);
extern uint64_t yang_get_default_uint64(const char *xpath_fmt, ...);

/* string */
extern struct yang_data *yang_data_new_string(const char *xpath,
					      const char *value);
extern const char *yang_dnode_get_string(const struct lyd_node *dnode,
					 const char *xpath_fmt, ...);
extern void yang_dnode_get_string_buf(char *buf, size_t size,
				      const struct lyd_node *dnode,
				      const char *xpath_fmt, ...);
extern const char *yang_get_default_string(const char *xpath_fmt, ...);
extern void yang_get_default_string_buf(char *buf, size_t size,
					const char *xpath_fmt, ...);

/* ip prefix */
extern void yang_str2prefix(const char *value, union prefixptr prefix);
extern struct yang_data *yang_data_new_prefix(const char *xpath,
					      union prefixconstptr prefix);
extern void yang_dnode_get_prefix(struct prefix *prefix,
				  const struct lyd_node *dnode,
				  const char *xpath_fmt, ...);
extern void yang_get_default_prefix(union prefixptr var, const char *xpath_fmt,
				    ...);

/* ipv4 */
extern void yang_str2ipv4(const char *value, struct in_addr *addr);
extern struct yang_data *yang_data_new_ipv4(const char *xpath,
					    const struct in_addr *addr);
extern void yang_dnode_get_ipv4(struct in_addr *addr,
				const struct lyd_node *dnode,
				const char *xpath_fmt, ...);
extern void yang_get_default_ipv4(struct in_addr *var, const char *xpath_fmt,
				  ...);

/* ipv4p */
extern void yang_str2ipv4p(const char *value, union prefixptr prefix);
extern struct yang_data *yang_data_new_ipv4p(const char *xpath,
					     union prefixconstptr prefix);
extern void yang_dnode_get_ipv4p(union prefixptr prefix,
				 const struct lyd_node *dnode,
				 const char *xpath_fmt, ...);
extern void yang_get_default_ipv4p(union prefixptr var, const char *xpath_fmt,
				   ...);

/* ipv6 */
extern void yang_str2ipv6(const char *value, struct in6_addr *addr);
extern struct yang_data *yang_data_new_ipv6(const char *xpath,
					    const struct in6_addr *addr);
extern void yang_dnode_get_ipv6(struct in6_addr *addr,
				const struct lyd_node *dnode,
				const char *xpath_fmt, ...);
extern void yang_get_default_ipv6(struct in6_addr *var, const char *xpath_fmt,
				  ...);

/* ipv6p */
extern void yang_str2ipv6p(const char *value, union prefixptr prefix);
extern struct yang_data *yang_data_new_ipv6p(const char *xpath,
					     union prefixconstptr prefix);
extern void yang_dnode_get_ipv6p(union prefixptr prefix,
				 const struct lyd_node *dnode,
				 const char *xpath_fmt, ...);
extern void yang_get_default_ipv6p(union prefixptr var, const char *xpath_fmt,
				   ...);

/* ip */
extern void yang_str2ip(const char *value, struct ipaddr *addr);
extern struct yang_data *yang_data_new_ip(const char *xpath,
					  const struct ipaddr *addr);
extern void yang_dnode_get_ip(struct ipaddr *addr, const struct lyd_node *dnode,
			      const char *xpath_fmt, ...);
extern void yang_get_default_ip(struct ipaddr *var, const char *xpath_fmt, ...);

#endif /* _FRR_NORTHBOUND_WRAPPERS_H_ */
