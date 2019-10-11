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

#include <zebra.h>

#include "log.h"
#include "lib_errors.h"
#include "northbound.h"

static const char *yang_get_default_value(const char *xpath)
{
	const struct lys_node *snode;
	const char *value;

	snode = ly_ctx_get_node(ly_native_ctx, NULL, xpath, 0);
	if (snode == NULL) {
		flog_err(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			 "%s: unknown data path: %s", __func__, xpath);
		zlog_backtrace(LOG_ERR);
		abort();
	}

	value = yang_snode_get_default(snode);
	assert(value);

	return value;
}

#define YANG_DNODE_GET_ASSERT(dnode, xpath)                                    \
	do {                                                                   \
		if ((dnode) == NULL) {                                         \
			flog_err(EC_LIB_YANG_DNODE_NOT_FOUND,                  \
				 "%s: couldn't find %s", __func__, (xpath));   \
			zlog_backtrace(LOG_ERR);                               \
			abort();                                               \
		}                                                              \
	} while (0)

/*
 * Primitive type: bool.
 */
bool yang_str2bool(const char *value)
{
	return strmatch(value, "true");
}

struct yang_data *yang_data_new_bool(const char *xpath, bool value)
{
	return yang_data_new(xpath, (value) ? "true" : "false");
}

bool yang_dnode_get_bool(const struct lyd_node *dnode, const char *xpath_fmt,
			 ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_BOOL);
	return dleaf->value.bln;
}

bool yang_get_default_bool(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2bool(value);
}

/*
 * Primitive type: dec64.
 */
double yang_str2dec64(const char *xpath, const char *value)
{
	double dbl = 0;

	if (sscanf(value, "%lf", &dbl) != 1) {
		flog_err(EC_LIB_YANG_DATA_CONVERT,
			 "%s: couldn't convert string to decimal64 [xpath %s]",
			 __func__, xpath);
		zlog_backtrace(LOG_ERR);
		abort();
	}

	return dbl;
}

struct yang_data *yang_data_new_dec64(const char *xpath, double value)
{
	char value_str[BUFSIZ];

	snprintf(value_str, sizeof(value_str), "%lf", value);
	return yang_data_new(xpath, value_str);
}

double yang_dnode_get_dec64(const struct lyd_node *dnode, const char *xpath_fmt,
			    ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_DEC64);

	return lyd_dec64_to_double(dnode);
}

double yang_get_default_dec64(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2dec64(xpath, value);
}

/*
 * Primitive type: enum.
 */
int yang_str2enum(const char *xpath, const char *value)
{
	const struct lys_node *snode;
	const struct lys_node_leaf *sleaf;
	const struct lys_type *type;
	const struct lys_type_info_enums *enums;

	snode = ly_ctx_get_node(ly_native_ctx, NULL, xpath, 0);
	if (snode == NULL) {
		flog_err(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			 "%s: unknown data path: %s", __func__, xpath);
		zlog_backtrace(LOG_ERR);
		abort();
	}

	sleaf = (const struct lys_node_leaf *)snode;
	type = &sleaf->type;
	enums = &type->info.enums;
	while (enums->count == 0 && type->der) {
		type = &type->der->type;
		enums = &type->info.enums;
	}
	for (unsigned int i = 0; i < enums->count; i++) {
		const struct lys_type_enum *enm = &enums->enm[i];

		if (strmatch(value, enm->name))
			return enm->value;
	}

	flog_err(EC_LIB_YANG_DATA_CONVERT,
		 "%s: couldn't convert string to enum [xpath %s]", __func__,
		 xpath);
	zlog_backtrace(LOG_ERR);
	abort();
}

struct yang_data *yang_data_new_enum(const char *xpath, int value)
{
	const struct lys_node *snode;
	const struct lys_node_leaf *sleaf;
	const struct lys_type *type;
	const struct lys_type_info_enums *enums;

	snode = ly_ctx_get_node(ly_native_ctx, NULL, xpath, 0);
	if (snode == NULL) {
		flog_err(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			 "%s: unknown data path: %s", __func__, xpath);
		zlog_backtrace(LOG_ERR);
		abort();
	}

	sleaf = (const struct lys_node_leaf *)snode;
	type = &sleaf->type;
	enums = &type->info.enums;
	while (enums->count == 0 && type->der) {
		type = &type->der->type;
		enums = &type->info.enums;
	}
	for (unsigned int i = 0; i < enums->count; i++) {
		const struct lys_type_enum *enm = &enums->enm[i];

		if (value == enm->value)
			return yang_data_new(xpath, enm->name);
	}

	flog_err(EC_LIB_YANG_DATA_CONVERT,
		 "%s: couldn't convert enum to string [xpath %s]", __func__,
		 xpath);
	zlog_backtrace(LOG_ERR);
	abort();
}

int yang_dnode_get_enum(const struct lyd_node *dnode, const char *xpath_fmt,
			...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_ENUM);
	return dleaf->value.enm->value;
}

int yang_get_default_enum(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2enum(xpath, value);
}

/*
 * Primitive type: int8.
 */
int8_t yang_str2int8(const char *value)
{
	return strtol(value, NULL, 10);
}

struct yang_data *yang_data_new_int8(const char *xpath, int8_t value)
{
	char value_str[BUFSIZ];

	snprintf(value_str, sizeof(value_str), "%d", value);
	return yang_data_new(xpath, value_str);
}

int8_t yang_dnode_get_int8(const struct lyd_node *dnode, const char *xpath_fmt,
			   ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_INT8);
	return dleaf->value.int8;
}

int8_t yang_get_default_int8(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2int8(value);
}

/*
 * Primitive type: int16.
 */
int16_t yang_str2int16(const char *value)
{
	return strtol(value, NULL, 10);
}

struct yang_data *yang_data_new_int16(const char *xpath, int16_t value)
{
	char value_str[BUFSIZ];

	snprintf(value_str, sizeof(value_str), "%d", value);
	return yang_data_new(xpath, value_str);
}

int16_t yang_dnode_get_int16(const struct lyd_node *dnode,
			     const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_INT16);
	return dleaf->value.int16;
}

int16_t yang_get_default_int16(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2int16(value);
}

/*
 * Primitive type: int32.
 */
int32_t yang_str2int32(const char *value)
{
	return strtol(value, NULL, 10);
}

struct yang_data *yang_data_new_int32(const char *xpath, int32_t value)
{
	char value_str[BUFSIZ];

	snprintf(value_str, sizeof(value_str), "%d", value);
	return yang_data_new(xpath, value_str);
}

int32_t yang_dnode_get_int32(const struct lyd_node *dnode,
			     const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_INT32);
	return dleaf->value.int32;
}

int32_t yang_get_default_int32(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2int32(value);
}

/*
 * Primitive type: int64.
 */
int64_t yang_str2int64(const char *value)
{
	return strtoll(value, NULL, 10);
}

struct yang_data *yang_data_new_int64(const char *xpath, int64_t value)
{
	char value_str[BUFSIZ];

	snprintf(value_str, sizeof(value_str), "%" PRId64, value);
	return yang_data_new(xpath, value_str);
}

int64_t yang_dnode_get_int64(const struct lyd_node *dnode,
			     const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_INT64);
	return dleaf->value.int64;
}

int64_t yang_get_default_int64(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2int64(value);
}

/*
 * Primitive type: uint8.
 */
uint8_t yang_str2uint8(const char *value)
{
	return strtoul(value, NULL, 10);
}

struct yang_data *yang_data_new_uint8(const char *xpath, uint8_t value)
{
	char value_str[BUFSIZ];

	snprintf(value_str, sizeof(value_str), "%u", value);
	return yang_data_new(xpath, value_str);
}

uint8_t yang_dnode_get_uint8(const struct lyd_node *dnode,
			     const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_UINT8);
	return dleaf->value.uint8;
}

uint8_t yang_get_default_uint8(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2uint8(value);
}

/*
 * Primitive type: uint16.
 */
uint16_t yang_str2uint16(const char *value)
{
	return strtoul(value, NULL, 10);
}

struct yang_data *yang_data_new_uint16(const char *xpath, uint16_t value)
{
	char value_str[BUFSIZ];

	snprintf(value_str, sizeof(value_str), "%u", value);
	return yang_data_new(xpath, value_str);
}

uint16_t yang_dnode_get_uint16(const struct lyd_node *dnode,
			       const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_UINT16);
	return dleaf->value.uint16;
}

uint16_t yang_get_default_uint16(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2uint16(value);
}

/*
 * Primitive type: uint32.
 */
uint32_t yang_str2uint32(const char *value)
{
	return strtoul(value, NULL, 10);
}

struct yang_data *yang_data_new_uint32(const char *xpath, uint32_t value)
{
	char value_str[BUFSIZ];

	snprintf(value_str, sizeof(value_str), "%u", value);
	return yang_data_new(xpath, value_str);
}

uint32_t yang_dnode_get_uint32(const struct lyd_node *dnode,
			       const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_UINT32);
	return dleaf->value.uint32;
}

uint32_t yang_get_default_uint32(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2uint32(value);
}

/*
 * Primitive type: uint64.
 */
uint64_t yang_str2uint64(const char *value)
{
	return strtoull(value, NULL, 10);
}

struct yang_data *yang_data_new_uint64(const char *xpath, uint64_t value)
{
	char value_str[BUFSIZ];

	snprintf(value_str, sizeof(value_str), "%" PRIu64, value);
	return yang_data_new(xpath, value_str);
}

uint64_t yang_dnode_get_uint64(const struct lyd_node *dnode,
			       const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_UINT64);
	return dleaf->value.uint64;
}

uint64_t yang_get_default_uint64(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	return yang_str2uint64(value);
}

/*
 * Primitive type: string.
 *
 * All string wrappers can be used with non-string types.
 */
struct yang_data *yang_data_new_string(const char *xpath, const char *value)
{
	return yang_data_new(xpath, value);
}

const char *yang_dnode_get_string(const struct lyd_node *dnode,
				  const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	return dleaf->value_str;
}

void yang_dnode_get_string_buf(char *buf, size_t size,
			       const struct lyd_node *dnode,
			       const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	if (strlcpy(buf, dleaf->value_str, size) >= size) {
		char xpath[XPATH_MAXLEN];

		yang_dnode_get_path(dnode, xpath, sizeof(xpath));
		flog_warn(EC_LIB_YANG_DATA_TRUNCATED,
			  "%s: value was truncated [xpath %s]", __func__,
			  xpath);
	}
}

const char *yang_get_default_string(const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	return yang_get_default_value(xpath);
}

void yang_get_default_string_buf(char *buf, size_t size, const char *xpath_fmt,
				 ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	if (strlcpy(buf, value, size) >= size)
		flog_warn(EC_LIB_YANG_DATA_TRUNCATED,
			  "%s: value was truncated [xpath %s]", __func__,
			  xpath);
}

/*
 * Derived type: IP prefix.
 */
void yang_str2prefix(const char *value, union prefixptr prefix)
{
	(void)str2prefix(value, prefix.p);
	apply_mask(prefix.p);
}

struct yang_data *yang_data_new_prefix(const char *xpath,
				       union prefixconstptr prefix)
{
	char value_str[PREFIX2STR_BUFFER];

	(void)prefix2str(prefix.p, value_str, sizeof(value_str));
	return yang_data_new(xpath, value_str);
}

void yang_dnode_get_prefix(struct prefix *prefix, const struct lyd_node *dnode,
			   const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	/*
	 * Initialize prefix to avoid static analyzer complaints about
	 * uninitialized memory.
	 */
	memset(prefix, 0, sizeof(*prefix));

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_STRING);
	(void)str2prefix(dleaf->value_str, prefix);
}

void yang_get_default_prefix(union prefixptr var, const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	yang_str2prefix(value, var);
}

/*
 * Derived type: ipv4.
 */
void yang_str2ipv4(const char *value, struct in_addr *addr)
{
	(void)inet_pton(AF_INET, value, addr);
}

struct yang_data *yang_data_new_ipv4(const char *xpath,
				     const struct in_addr *addr)
{
	char value_str[INET_ADDRSTRLEN];

	(void)inet_ntop(AF_INET, addr, value_str, sizeof(value_str));
	return yang_data_new(xpath, value_str);
}

void yang_dnode_get_ipv4(struct in_addr *addr, const struct lyd_node *dnode,
			 const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_STRING);
	(void)inet_pton(AF_INET, dleaf->value_str, addr);
}

void yang_get_default_ipv4(struct in_addr *var, const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	yang_str2ipv4(value, var);
}

/*
 * Derived type: ipv4p.
 */
void yang_str2ipv4p(const char *value, union prefixptr prefix)
{
	struct prefix_ipv4 *prefix4 = prefix.p4;

	(void)str2prefix_ipv4(value, prefix4);
	apply_mask_ipv4(prefix4);
}

struct yang_data *yang_data_new_ipv4p(const char *xpath,
				      union prefixconstptr prefix)
{
	char value_str[PREFIX2STR_BUFFER];

	(void)prefix2str(prefix.p, value_str, sizeof(value_str));
	return yang_data_new(xpath, value_str);
}

void yang_dnode_get_ipv4p(union prefixptr prefix, const struct lyd_node *dnode,
			  const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;
	struct prefix_ipv4 *prefix4 = prefix.p4;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_STRING);
	(void)str2prefix_ipv4(dleaf->value_str, prefix4);
}

void yang_get_default_ipv4p(union prefixptr var, const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	yang_str2ipv4p(value, var);
}

/*
 * Derived type: ipv6.
 */
void yang_str2ipv6(const char *value, struct in6_addr *addr)
{
	(void)inet_pton(AF_INET6, value, addr);
}

struct yang_data *yang_data_new_ipv6(const char *xpath,
				     const struct in6_addr *addr)
{
	char value_str[INET6_ADDRSTRLEN];

	(void)inet_ntop(AF_INET6, addr, value_str, sizeof(value_str));
	return yang_data_new(xpath, value_str);
}

void yang_dnode_get_ipv6(struct in6_addr *addr, const struct lyd_node *dnode,
			 const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_STRING);
	(void)inet_pton(AF_INET6, dleaf->value_str, addr);
}

void yang_get_default_ipv6(struct in6_addr *var, const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	yang_str2ipv6(value, var);
}

/*
 * Derived type: ipv6p.
 */
void yang_str2ipv6p(const char *value, union prefixptr prefix)
{
	struct prefix_ipv6 *prefix6 = prefix.p6;

	(void)str2prefix_ipv6(value, prefix6);
	apply_mask_ipv6(prefix6);
}

struct yang_data *yang_data_new_ipv6p(const char *xpath,
				      union prefixconstptr prefix)
{
	char value_str[PREFIX2STR_BUFFER];

	(void)prefix2str(prefix.p, value_str, sizeof(value_str));
	return yang_data_new(xpath, value_str);
}

void yang_dnode_get_ipv6p(union prefixptr prefix, const struct lyd_node *dnode,
			  const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;
	struct prefix_ipv6 *prefix6 = prefix.p6;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_STRING);
	(void)str2prefix_ipv6(dleaf->value_str, prefix6);
}

void yang_get_default_ipv6p(union prefixptr var, const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	yang_str2ipv6p(value, var);
}

/*
 * Derived type: ip.
 */
void yang_str2ip(const char *value, struct ipaddr *ip)
{
	(void)str2ipaddr(value, ip);
}

struct yang_data *yang_data_new_ip(const char *xpath, const struct ipaddr *addr)
{
	size_t sz = IS_IPADDR_V4(addr) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
	char value_str[sz];

	ipaddr2str(addr, value_str, sizeof(value_str));
	return yang_data_new(xpath, value_str);
}

void yang_dnode_get_ip(struct ipaddr *addr, const struct lyd_node *dnode,
		       const char *xpath_fmt, ...)
{
	const struct lyd_node_leaf_list *dleaf;

	assert(dnode);
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);
		dnode = yang_dnode_get(dnode, xpath);
		YANG_DNODE_GET_ASSERT(dnode, xpath);
	}

	dleaf = (const struct lyd_node_leaf_list *)dnode;
	assert(dleaf->value_type == LY_TYPE_STRING);
	(void)str2ipaddr(dleaf->value_str, addr);
}

void yang_get_default_ip(struct ipaddr *var, const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	const char *value;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	value = yang_get_default_value(xpath);
	yang_str2ip(value, var);
}
