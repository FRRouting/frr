// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "base64.h"
#include "log.h"
#include "lib_errors.h"
#include "northbound.h"
#include "printfrr.h"
#include "nexthop.h"
#include "printfrr.h"


#define YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt)                           \
	({                                                                     \
		va_list __ap;                                                  \
		va_start(__ap, (xpath_fmt));                                   \
		const struct lyd_value *__dvalue =                             \
			yang_dnode_xpath_get_value(dnode, xpath_fmt, __ap);    \
		va_end(__ap);                                                  \
		__dvalue;                                                      \
	})

#define YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt)                           \
	({                                                                     \
		va_list __ap;                                                  \
		va_start(__ap, (xpath_fmt));                                   \
		const char *__canon =                                          \
			yang_dnode_xpath_get_canon(dnode, xpath_fmt, __ap);    \
		va_end(__ap);                                                  \
		__canon;                                                       \
	})

#define YANG_DNODE_GET_ASSERT(dnode, xpath)                                    \
	do {                                                                   \
		if ((dnode) == NULL) {                                         \
			flog_err(EC_LIB_YANG_DNODE_NOT_FOUND,                  \
				 "%s: couldn't find %s", __func__, (xpath));   \
			zlog_backtrace(LOG_ERR);                               \
			abort();                                               \
		}                                                              \
	} while (0)

PRINTFRR(2, 0)
static inline const char *
yang_dnode_xpath_get_canon(const struct lyd_node *dnode, const char *xpath_fmt,
			   va_list ap)
{
	const struct lyd_node_term *__dleaf =
		(const struct lyd_node_term *)dnode;
	assert(__dleaf);
	if (xpath_fmt) {
		char __xpath[XPATH_MAXLEN];
		vsnprintf(__xpath, sizeof(__xpath), xpath_fmt, ap);
		__dleaf = (const struct lyd_node_term *)yang_dnode_get(dnode,
								       __xpath);
		YANG_DNODE_GET_ASSERT(__dleaf, __xpath);
	}
	return lyd_get_value(&__dleaf->node);
}

PRINTFRR(2, 0)
static inline const struct lyd_value *
yang_dnode_xpath_get_value(const struct lyd_node *dnode, const char *xpath_fmt,
			   va_list ap)
{
	const struct lyd_node_term *__dleaf =
		(const struct lyd_node_term *)dnode;
	assert(__dleaf);
	if (xpath_fmt) {
		char __xpath[XPATH_MAXLEN];
		vsnprintf(__xpath, sizeof(__xpath), xpath_fmt, ap);
		__dleaf = (const struct lyd_node_term *)yang_dnode_get(dnode,
								       __xpath);
		YANG_DNODE_GET_ASSERT(__dleaf, __xpath);
	}
	const struct lyd_value *__dvalue = &__dleaf->value;
	if (__dvalue->realtype->basetype == LY_TYPE_UNION)
		__dvalue = &__dvalue->subvalue->value;
	return __dvalue;
}

static const char *yang_get_default_value(const char *xpath)
{
	const struct lysc_node *snode;
	const char *value;

	snode = yang_find_snode(ly_native_ctx, xpath, 0);
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
	const struct lyd_value *dvalue;
	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_BOOL);
	return dvalue->boolean;
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
	const double denom[19] = { 1e0,	 1e1,  1e2,  1e3,  1e4,	 1e5,  1e6,
				   1e7,	 1e8,  1e9,  1e10, 1e11, 1e12, 1e13,
				   1e14, 1e15, 1e16, 1e17, 1e18 };
	const struct lysc_type_dec *dectype;
	const struct lyd_value *dvalue;

	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	dectype = (const struct lysc_type_dec *)dvalue->realtype;
	assert(dectype->basetype == LY_TYPE_DEC64);
	assert(dectype->fraction_digits < sizeof(denom) / sizeof(*denom));
	return (double)dvalue->dec64 / denom[dectype->fraction_digits];
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
	const struct lysc_node *snode;
	const struct lysc_node_leaf *sleaf;
	const struct lysc_type_enum *type;
	const struct lysc_type_bitenum_item *enums;

	snode = yang_find_snode(ly_native_ctx, xpath, 0);
	if (snode == NULL) {
		flog_err(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			 "%s: unknown data path: %s", __func__, xpath);
		zlog_backtrace(LOG_ERR);
		abort();
	}

	assert(snode->nodetype == LYS_LEAF);
	sleaf = (const struct lysc_node_leaf *)snode;
	type = (const struct lysc_type_enum *)sleaf->type;
	assert(type->basetype == LY_TYPE_ENUM);
	enums = type->enums;
	unsigned int count = LY_ARRAY_COUNT(enums);
	for (unsigned int i = 0; i < count; i++) {
		if (strmatch(value, enums[i].name)) {
			assert(CHECK_FLAG(enums[i].flags, LYS_SET_VALUE));
			return enums[i].value;
		}
	}

	flog_err(EC_LIB_YANG_DATA_CONVERT,
		 "%s: couldn't convert string to enum [xpath %s]", __func__,
		 xpath);
	zlog_backtrace(LOG_ERR);
	abort();
}

struct yang_data *yang_data_new_enum(const char *xpath, int value)
{
	const struct lysc_node *snode;
	const struct lysc_node_leaf *sleaf;
	const struct lysc_type_enum *type;
	const struct lysc_type_bitenum_item *enums;

	snode = yang_find_snode(ly_native_ctx, xpath, 0);
	if (snode == NULL) {
		flog_err(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			 "%s: unknown data path: %s", __func__, xpath);
		zlog_backtrace(LOG_ERR);
		abort();
	}

	assert(snode->nodetype == LYS_LEAF);
	sleaf = (const struct lysc_node_leaf *)snode;
	type = (const struct lysc_type_enum *)sleaf->type;
	assert(type->basetype == LY_TYPE_ENUM);
	enums = type->enums;
	unsigned int count = LY_ARRAY_COUNT(enums);
	for (unsigned int i = 0; i < count; i++) {
		if (CHECK_FLAG(enums[i].flags, LYS_SET_VALUE)
		    && value == enums[i].value)
			return yang_data_new(xpath, enums[i].name);
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
	const struct lyd_value *dvalue;

	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_ENUM);
	assert(dvalue->enum_item->flags & LYS_SET_VALUE);
	return dvalue->enum_item->value;
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
	const struct lyd_value *dvalue;
	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_INT8);
	return dvalue->int8;
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
	const struct lyd_value *dvalue;
	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_INT16);
	return dvalue->int16;
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
	const struct lyd_value *dvalue;
	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_INT32);
	return dvalue->int32;
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

	snprintfrr(value_str, sizeof(value_str), "%" PRId64, value);
	return yang_data_new(xpath, value_str);
}

int64_t yang_dnode_get_int64(const struct lyd_node *dnode,
			     const char *xpath_fmt, ...)
{
	const struct lyd_value *dvalue;
	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_INT64);
	return dvalue->int64;
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
	const struct lyd_value *dvalue;
	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_UINT8);
	return dvalue->uint8;
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
	const struct lyd_value *dvalue;
	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_UINT16);
	return dvalue->uint16;
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
	const struct lyd_value *dvalue;
	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_UINT32);
	return dvalue->uint32;
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

	snprintfrr(value_str, sizeof(value_str), "%" PRIu64, value);
	return yang_data_new(xpath, value_str);
}

uint64_t yang_dnode_get_uint64(const struct lyd_node *dnode,
			       const char *xpath_fmt, ...)
{
	const struct lyd_value *dvalue;
	dvalue = YANG_DNODE_XPATH_GET_VALUE(dnode, xpath_fmt);
	assert(dvalue->realtype->basetype == LY_TYPE_UINT64);
	return dvalue->uint64;
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
	return YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
}

void yang_dnode_get_string_buf(char *buf, size_t size,
			       const struct lyd_node *dnode,
			       const char *xpath_fmt, ...)
{
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	if (strlcpy(buf, canon, size) >= size) {
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
 * Primitive type: binary.
 */
struct yang_data *yang_data_new_binary(const char *xpath, const char *value,
				       size_t len)
{
	char *value_str;
	struct base64_encodestate s;
	int cnt;
	char *c;
	struct yang_data *data;

	value_str = (char *)malloc(len * 2);
	base64_init_encodestate(&s);
	cnt = base64_encode_block(value, len, value_str, &s);
	c = value_str + cnt;
	cnt = base64_encode_blockend(c, &s);
	c += cnt;
	*c = 0;
	data = yang_data_new(xpath, value_str);
	free(value_str);
	return data;
}

size_t yang_dnode_get_binary_buf(char *buf, size_t size,
				 const struct lyd_node *dnode,
				 const char *xpath_fmt, ...)
{
	const char *canon;
	size_t cannon_len;
	size_t decode_len;
	size_t ret_len;
	size_t cnt;
	char *value_str;
	struct base64_decodestate s;

	canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	cannon_len = strlen(canon);
	decode_len = cannon_len + 1;
	value_str = (char *)malloc(decode_len);
	base64_init_decodestate(&s);
	cnt = base64_decode_block(canon, cannon_len, value_str, &s);

	ret_len = size > cnt ? cnt : size;
	memcpy(buf, value_str, ret_len);
	if (size < cnt) {
		char xpath[XPATH_MAXLEN];

		yang_dnode_get_path(dnode, xpath, sizeof(xpath));
		flog_warn(EC_LIB_YANG_DATA_TRUNCATED,
			  "%s: value was truncated [xpath %s]", __func__,
			  xpath);
	}
	free(value_str);
	return ret_len;
}


/*
 * Primitive type: empty.
 */
struct yang_data *yang_data_new_empty(const char *xpath)
{
	return yang_data_new(xpath, NULL);
}

bool yang_dnode_get_empty(const struct lyd_node *dnode, const char *xpath_fmt,
			  ...)
{
	va_list ap;
	char xpath[XPATH_MAXLEN];
	const struct lyd_node_term *dleaf;

	assert(dnode);

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	dnode = yang_dnode_get(dnode, xpath);
	if (dnode) {
		dleaf = (const struct lyd_node_term *)dnode;
		if (dleaf->value.realtype->basetype == LY_TYPE_EMPTY)
			return true;
	}

	return false;
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
	const char *canon;
	/*
	 * Initialize prefix to avoid static analyzer complaints about
	 * uninitialized memory.
	 */
	memset(prefix, 0, sizeof(*prefix));

	/* XXX ip_prefix is a native type now in ly2, leverage? */
	canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	(void)str2prefix(canon, prefix);
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
	/* XXX libyang2 IPv4 address is a native type now in ly2 */
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	(void)inet_pton(AF_INET, canon, addr);
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
	struct prefix_ipv4 *prefix4 = prefix.p4;
	/* XXX libyang2: ipv4/6 address is a native type now in ly2 */
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	(void)str2prefix_ipv4(canon, prefix4);
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
	/* XXX libyang2: IPv6 address is a native type now, leverage. */
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	(void)inet_pton(AF_INET6, canon, addr);
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
	struct prefix_ipv6 *prefix6 = prefix.p6;

	/* XXX IPv6 address is a native type now in ly2 -- can we leverage? */
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	(void)str2prefix_ipv6(canon, prefix6);
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
	/* XXX IPv4 address could be a plugin type now in ly2, leverage? */
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	(void)str2ipaddr(canon, addr);
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

struct yang_data *yang_data_new_mac(const char *xpath,
				    const struct ethaddr *mac)
{
	char value_str[ETHER_ADDR_STRLEN];

	prefix_mac2str(mac, value_str, sizeof(value_str));
	return yang_data_new(xpath, value_str);
}

void yang_str2mac(const char *value, struct ethaddr *mac)
{
	(void)prefix_str2mac(value, mac);
}

void yang_dnode_get_mac(struct ethaddr *mac, const struct lyd_node *dnode,
			const char *xpath_fmt, ...)
{
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	(void)prefix_str2mac(canon, mac);
}

struct yang_data *yang_data_new_date_and_time(const char *xpath, time_t time, bool is_monotime)
{
	struct yang_data *yd;
	char *times = NULL;

	if (is_monotime) {
		struct timeval _time = { time, 0 };
		struct timeval time_real;

		monotime_to_realtime(&_time, &time_real);
		time = time_real.tv_sec;
	}

	(void)ly_time_time2str(time, NULL, &times);
	yd = yang_data_new(xpath, times);
	free(times);

	return yd;
}

struct timespec yang_dnode_get_date_and_timespec(const struct lyd_node *dnode,
						 const char *xpath_fmt, ...)
{
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	struct timespec ts;
	LY_ERR err;

	err = ly_time_str2ts(canon, &ts);
	assert(!err);

	return ts;
}

time_t yang_dnode_get_date_and_time(const struct lyd_node *dnode,
				    const char *xpath_fmt, ...)
{
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	time_t time;
	LY_ERR err;

	err = ly_time_str2time(canon, &time, NULL);
	assert(!err);

	return time;
}

float yang_dnode_get_bandwidth_ieee_float32(const struct lyd_node *dnode,
					    const char *xpath_fmt, ...)
{
	const char *canon = YANG_DNODE_XPATH_GET_CANON(dnode, xpath_fmt);
	float value;

	assert(sscanf(canon, "%a", &value) == 1);

	return value;
}

const char *yang_nexthop_type2str(uint32_t ntype)
{
	switch (ntype) {
	case NEXTHOP_TYPE_IFINDEX:
		return "ifindex";
		break;
	case NEXTHOP_TYPE_IPV4:
		return "ip4";
		break;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		return "ip4-ifindex";
		break;
	case NEXTHOP_TYPE_IPV6:
		return "ip6";
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		return "ip6-ifindex";
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		return "blackhole";
		break;
	default:
		return "unknown";
		break;
	}
}


const char *yang_afi_safi_value2identity(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP && safi == SAFI_UNICAST)
		return "frr-routing:ipv4-unicast";
	if (afi == AFI_IP6 && safi == SAFI_UNICAST)
		return "frr-routing:ipv6-unicast";
	if (afi == AFI_IP && safi == SAFI_MULTICAST)
		return "frr-routing:ipv4-multicast";
	if (afi == AFI_IP6 && safi == SAFI_MULTICAST)
		return "frr-routing:ipv6-multicast";
	if (afi == AFI_IP && safi == SAFI_MPLS_VPN)
		return "frr-routing:l3vpn-ipv4-unicast";
	if (afi == AFI_IP6 && safi == SAFI_MPLS_VPN)
		return "frr-routing:l3vpn-ipv6-unicast";
	if (afi == AFI_L2VPN && safi == SAFI_EVPN)
		return "frr-routing:l2vpn-evpn";
	if (afi == AFI_IP && safi == SAFI_LABELED_UNICAST)
		return "frr-routing:ipv4-labeled-unicast";
	if (afi == AFI_IP6 && safi == SAFI_LABELED_UNICAST)
		return "frr-routing:ipv6-labeled-unicast";
	if (afi == AFI_IP && safi == SAFI_FLOWSPEC)
		return "frr-routing:ipv4-flowspec";
	if (afi == AFI_IP6 && safi == SAFI_FLOWSPEC)
		return "frr-routing:ipv6-flowspec";

	return NULL;
}

void yang_afi_safi_identity2value(const char *key, afi_t *afi, safi_t *safi)
{
	if (strmatch(key, "frr-routing:ipv4-unicast")) {
		*afi = AFI_IP;
		*safi = SAFI_UNICAST;
	} else if (strmatch(key, "frr-routing:ipv6-unicast")) {
		*afi = AFI_IP6;
		*safi = SAFI_UNICAST;
	} else if (strmatch(key, "frr-routing:ipv4-multicast")) {
		*afi = AFI_IP;
		*safi = SAFI_MULTICAST;
	} else if (strmatch(key, "frr-routing:ipv6-multicast")) {
		*afi = AFI_IP6;
		*safi = SAFI_MULTICAST;
	} else if (strmatch(key, "frr-routing:l3vpn-ipv4-unicast")) {
		*afi = AFI_IP;
		*safi = SAFI_MPLS_VPN;
	} else if (strmatch(key, "frr-routing:l3vpn-ipv6-unicast")) {
		*afi = AFI_IP6;
		*safi = SAFI_MPLS_VPN;
	} else if (strmatch(key, "frr-routing:ipv4-labeled-unicast")) {
		*afi = AFI_IP;
		*safi = SAFI_LABELED_UNICAST;
	} else if (strmatch(key, "frr-routing:ipv6-labeled-unicast")) {
		*afi = AFI_IP6;
		*safi = SAFI_LABELED_UNICAST;
	} else if (strmatch(key, "frr-routing:l2vpn-evpn")) {
		*afi = AFI_L2VPN;
		*safi = SAFI_EVPN;
	} else if (strmatch(key, "frr-routing:ipv4-flowspec")) {
		*afi = AFI_IP;
		*safi = SAFI_FLOWSPEC;
	} else if (strmatch(key, "frr-routing:ipv6-flowspec")) {
		*afi = AFI_IP6;
		*safi = SAFI_FLOWSPEC;
	} else {
		*afi = AFI_UNSPEC;
		*safi = SAFI_UNSPEC;
	}
}
