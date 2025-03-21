// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 fenglei <fengleiljx@gmail.com>
 *
 */
#include <zebra.h>

#include "log.h"
#include "lib_errors.h"
#include "hook.h"
#include "module.h"
#include "libfrr.h"
#include "frrevent.h"
#include "command.h"
#include "debug.h"
#include "memory.h"
#include "lib/version.h"
#include "northbound.h"
#include "frr_pthread.h"

#include <stdint.h>
#include <string.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>

#include <hiredis/adapters/libuv.h>
#include <uv.h>

DEFINE_MTYPE(LIB, HIREDIS, "Hiredis module");

#define hiredis_white_space(ch) (isspace(ch))

#define HIREDIS_DEFAULT_PORT 6379

static struct debug nb_dbg_client_hiredis = {0, "Northbound client: Hiredis"};
static struct frr_pthread *fpt;
static struct event_loop *master;
static struct nb_transaction *transaction;

// #define HIREDIS_UNUSED

#define MAXIMUM_CHANNEL_NUM 10
static const char *hiredis_sub_channels[][MAXIMUM_CHANNEL_NUM] = {
	{"BABEL", "frr-babel", NULL},
	{"BFD", "frr-bfd", NULL},
	{"BGP", "frr-bgp", NULL},
	{"ERGRP", "frr-eigrp", NULL},	
	{"FABRIC", "frr-fabric", NULL},
	{"ISIS", "frr-isis", NULL},
	{"LDP", "frr-ldp", NULL},
	{"MGMT", "frr-mgmt", NULL},
	{"NHRP", "frr-nhrp", NULL},
	{"OSPF6", "frr-ospf6", NULL},		
	{"OSPF", "frr-ospf", NULL},
	{"PATH", "frr-path", NULL},
	{"PBR", "frr-pbr", NULL},
	{"PIM6", "frr-pim6", NULL},	
	{"PIM", "frr-pim", NULL},
	{"RIP", "frr-rip", NULL},	
	{"RIPNG", "frr-ripng", NULL},
	{"STATIC", "frr-static", NULL},
	{"VRRP", "frr-vrrp", NULL},
	{"ZEBRA", "frr-zebra", NULL},
	{NULL, NULL, NULL}
};

/**
 * @brief Type of the operation made on an item, used by changeset retrieval in ::sr_get_change_next.
 */
typedef enum {
    HI_OP_CREATED,   /**< The item has been created by the change. */
    HI_OP_MODIFIED,  /**< The value of the item has been modified by the change. */
    HI_OP_DELETED,   /**< The item has been deleted by the change. */
    HI_OP_MOVED,      /**< The item has been moved in the subtree by the change (applicable for leaf-lists and user-ordered lists). */
    HI_OP_SELECT,
    HI_OP_UNKNOW,
} hi_change_oper_t;

const char *hi_change_oper_str[] = {
	"create",
	"modify",
	"delete",
	"move",
	"select",
	"unknow"
};

/**
 * @brief Possible types of a data element stored in the sysrepo datastore.
 */
typedef enum {
    /* special types that does not contain any data */
    HI_UNKNOWN_T,              /**< Element unknown to sysrepo (unsupported element). */

    HI_LIST_T,                 /**< List instance. ([RFC 7950 sec 7.8](http://tools.ietf.org/html/rfc7950#section-7.8)) */
    HI_CONTAINER_T,            /**< Non-presence container. ([RFC 7950 sec 7.5](http://tools.ietf.org/html/rfc7950#section-7.5)) */
    HI_CONTAINER_PRESENCE_T,   /**< Presence container. ([RFC 7950 sec 7.5.1](http://tools.ietf.org/html/rfc7950#section-7.5.1)) */
    HI_LEAF_EMPTY_T,           /**< A leaf that does not hold any value ([RFC 7950 sec 9.11](http://tools.ietf.org/html/rfc7950#section-9.11)) */
    HI_NOTIFICATION_T,         /**< Notification instance ([RFC 7095 sec 7.16](https://tools.ietf.org/html/rfc7950#section-7.16)) */

    /* types containing some data */
    HI_BINARY_T,       /**< Base64-encoded binary data ([RFC 7950 sec 9.8](http://tools.ietf.org/html/rfc7950#section-9.8)) */
    HI_BITS_T,         /**< A set of bits or flags ([RFC 7950 sec 9.7](http://tools.ietf.org/html/rfc7950#section-9.7)) */
    HI_BOOL_T,         /**< A boolean value ([RFC 7950 sec 9.5](http://tools.ietf.org/html/rfc7950#section-9.5)) */
    HI_DECIMAL64_T,    /**< 64-bit signed decimal number ([RFC 7950 sec 9.3](http://tools.ietf.org/html/rfc7950#section-9.3)) */
    HI_ENUM_T,         /**< A string from enumerated strings list ([RFC 7950 sec 9.6](http://tools.ietf.org/html/rfc7950#section-9.6)) */
    HI_IDENTITYREF_T,  /**< A reference to an abstract identity ([RFC 7950 sec 9.10](http://tools.ietf.org/html/rfc7950#section-9.10)) */
    HI_INSTANCEID_T,   /**< References a data tree node ([RFC 7950 sec 9.13](http://tools.ietf.org/html/rfc7950#section-9.13)) */
    HI_INT8_T,         /**< 8-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    HI_INT16_T,        /**< 16-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    HI_INT32_T,        /**< 32-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    HI_INT64_T,        /**< 64-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    HI_STRING_T,       /**< Human-readable string ([RFC 7950 sec 9.4](http://tools.ietf.org/html/rfc7950#section-9.4)) */
    HI_UINT8_T,        /**< 8-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    HI_UINT16_T,       /**< 16-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    HI_UINT32_T,       /**< 32-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    HI_UINT64_T,       /**< 64-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    HI_ANYXML_T,       /**< Unknown chunk of XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
    HI_ANYDATA_T       /**< Unknown set of nodes, encoded in XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
} hi_val_type_t;

/**
 * @brief Data of an element (if applicable), properly set according to the type.
 */
union hi_val_data_u {
    char *binary_val;       /**< Base64-encoded binary data ([RFC 7950 sec 9.8](http://tools.ietf.org/html/rfc7950#section-9.8)) */
    char *bits_val;         /**< A set of bits or flags ([RFC 7950 sec 9.7](http://tools.ietf.org/html/rfc7950#section-9.7)) */
    int bool_val;           /**< A boolean value ([RFC 7950 sec 9.5](http://tools.ietf.org/html/rfc7950#section-9.5)) */
    double decimal64_val;   /**< 64-bit signed decimal number ([RFC 7950 sec 9.3](http://tools.ietf.org/html/rfc7950#section-9.3))
                                 __Be careful with this value!__ It is not always possible and the value can change when converting
                                 between a double and YANG decimal64. Because of that you may see some unexpected behavior setting
                                 or reading this value. To avoid these problems, use `*_tree()` API variants instead. */
    char *enum_val;         /**< A string from enumerated strings list ([RFC 7950 sec 9.6](http://tools.ietf.org/html/rfc7950#section-9.6)) */
    char *identityref_val;  /**< A reference to an abstract identity ([RFC 7950 sec 9.10](http://tools.ietf.org/html/rfc7950#section-9.10)) */
    char *instanceid_val;   /**< References a data tree node ([RFC 7950 sec 9.13](http://tools.ietf.org/html/rfc7950#section-9.13)) */
    int8_t int8_val;        /**< 8-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    int16_t int16_val;      /**< 16-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    int32_t int32_val;      /**< 32-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    int64_t int64_val;      /**< 64-bit signed integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    char *string_val;       /**< Human-readable string ([RFC 7950 sec 9.4](http://tools.ietf.org/html/rfc7950#section-9.4)) */
    uint8_t uint8_val;      /**< 8-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    uint16_t uint16_val;    /**< 16-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    uint32_t uint32_val;    /**< 32-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    uint64_t uint64_val;    /**< 64-bit unsigned integer ([RFC 7950 sec 9.2](https://tools.ietf.org/html/rfc7950#section-9.2)) */
    char *anyxml_val;       /**< Unknown chunk of XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
    char *anydata_val;      /**< Unknown set of nodes, encoded in XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
};

typedef union hi_val_data_u hi_val_data_t;

struct hi_val_s {
	char *xpath;
	hi_val_type_t type;
	int dflt;
	char *origin;
	hi_val_data_t data;
};

typedef struct hi_val_s hi_val_t;

struct hi_change_iter_s {	
    struct lyd_node *diff; /* optional */
	struct ly_set *set;
	uint32_t idx; /* iterator set->count */
};

typedef struct hi_change_iter_s hi_change_iter_t;

struct hiredis_main {
	uint16_t              port;
	
	redisContext          *context;
	redisAsyncContext     *uv_context;

	/* based libuv asyn call, you may choose libevent */	
	uv_loop_t             *uv_loop;

	struct event          *event;	
};

static struct hiredis_main hiredis_main, *hm = &hiredis_main;

/* ******************************* function statement start **************************************** */

// cli function
static void frr_hiredis_cli_init(void);

// hiredis xpath pair api
static void hiredis_free_change_iter(hi_change_iter_t *iter);
static void hiredis_free_val(hi_val_t *value);
static bool hiredis_get_operation(char *msg, hi_change_oper_t *operation);

static bool hiredis_get_changes_iter(const char *str, LYD_FORMAT format, hi_change_iter_t **it);
static void hiredis_edit_diff_get_origin(const struct lyd_node *node, char **origin, int *origin_own);
static bool hiredis_val_ly2sr(const struct lyd_node *node, hi_val_t *sr_val);
static void * hiredis_realloc(void *ptr, size_t size);
static bool hiredis_change_ly2sr(const struct lyd_node *node, const char *value_str,
	const char *anchor, hi_val_t **sr_val_p);
static bool hiredis_set_getnext(struct ly_set *set, uint32_t *idx, struct lyd_node **node);
static bool hiredis_get_change_next(hi_change_iter_t *iter, hi_change_oper_t operation,
	hi_val_t **old_value, hi_val_t **new_value);
static int hiredis_val_to_buff(const hi_val_t *value, char buffer[], size_t size);
static int frr_hiredis_process_change(struct nb_config *candidate,
	 hi_change_oper_t sr_op, hi_val_t *sr_old_val, hi_val_t *sr_new_val);
static bool hiredis_config_change(const char *str, LYD_FORMAT format, hi_change_oper_t op);
static bool frr_hiredis_change_apply(struct nb_config *candidate);

static bool frr_hiredis_get_path(const char *xpath, 
						  LYD_FORMAT lyd_format, bool with_defaults);

// cuda operation api
static LY_ERR hiredis_data_tree_from_dnode(const struct lyd_node *dnode,
					      LYD_FORMAT lyd_format, bool with_defaults);

static struct lyd_node *hiredis_get_dnode_config(const char *xpath);

static struct lyd_node *hiredis_get_dnode_state(const char *xpath);

// event schedule and daemon function
static void hiredis_match_event(struct event *event);
static bool frr_daemon_sub_channel(const char *daemon_name);

// hiredis uv asynchronized msg api
static void hiredis_uv_subscribe(const char *channel);
static bool hiredis_uv_connect(void);
static void hiredis_uv_cb(redisAsyncContext *c, void *reply, void *privdata);
static void hiredis_uv_connect_cb(const redisAsyncContext *c, int status);
static void hiredis_uv_disconnect_cb(const redisAsyncContext *c, int status);

static void *hiredis_pthread_start(void *arg);

/* ******************************* function statement end   **************************************** */


/* ******************************* cli function start ********************************************** */

DEFUN (debug_nb_hiredis,
       debug_nb_hiredis_cmd,
       "[no] debug northbound client redis",
       NO_STR
       DEBUG_STR
       "Northbound debugging\n"
       "Client\n"
       "redis\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, "no");

	DEBUG_MODE_SET(&nb_dbg_client_hiredis, mode, !no);

	vty_out(vty, "debug rdis client.\n");

	return CMD_SUCCESS;
}

static void frr_hiredis_cli_init(void)
{
	debug_install(&nb_dbg_client_hiredis);

	install_element(ENABLE_NODE, &debug_nb_hiredis_cmd);
	install_element(CONFIG_NODE, &debug_nb_hiredis_cmd);
}

/* ******************************* cli function end   ********************************************** */


/* ******************************* xpath function start ******************************************** */
static void hiredis_free_change_iter(hi_change_iter_t *iter)
{
    if (!iter) {
        return;
    }

    lyd_free_all(iter->diff);
    ly_set_free(iter->set, NULL);
    free(iter);
}


static void hiredis_free_val(hi_val_t *value)
{
	int type;
    if (!value) {
        return;
    }

    free(value->xpath);
    free(value->origin);

	type = value->type;
    switch (type) {
    case HI_BINARY_T:
    case HI_BITS_T:
    case HI_ENUM_T:
    case HI_IDENTITYREF_T:
    case HI_INSTANCEID_T:
    case HI_STRING_T:
    case HI_ANYXML_T:
    case HI_ANYDATA_T:
        free(value->data.string_val);
        break;
    default:
        /* nothing to free */
        break;
    }

    free(value);
}

static bool hiredis_get_operation(char *msg, hi_change_oper_t *operation)
{
	int len;
	hi_change_oper_t op;

	if (!msg || !operation)
		return false;

	while (hiredis_white_space((uint8_t)*msg) && *msg != '\0')
		msg++;
	
	if (msg == NULL || *msg == '\0')
		return false;

	for (op = HI_OP_CREATED; op < HI_OP_UNKNOW; ++op) {

		len = strlen(hi_change_oper_str[op]);		
		
		if (strncasecmp(msg, hi_change_oper_str[op], len) == 0) {

			break;
		}
	}

	if (op == HI_OP_UNKNOW)
		return false;

	*operation = op;
	return true;
}

static bool frr_hiredis_get_path(const char *xpath, 
	LYD_FORMAT lyd_format, bool with_defaults)
{	
	struct lyd_node *dnode_config = NULL;
	struct lyd_node *dnode_state = NULL;
	struct lyd_node *dnode_final;
	
	dnode_config = hiredis_get_dnode_config(xpath);
	if (!dnode_config)
		return false;

	dnode_state = hiredis_get_dnode_state(xpath);
	if (!dnode_state) {
		if(dnode_config)
			yang_dnode_free(dnode_config);

		return false;
	}

	if (lyd_merge_siblings(&dnode_state, dnode_config,
		       LYD_MERGE_DESTRUCT)
    != LY_SUCCESS) {
		yang_dnode_free(dnode_state);
		yang_dnode_free(dnode_config);
		return false;
    }
	
	dnode_final = dnode_state;

	LY_ERR err = lyd_validate_all(&dnode_final, ly_native_ctx,
				      0, NULL);

	if (err) {

		flog_err(EC_LIB_HIREDIS_INIT,
				"%s validate lyd_validate_all() failed: %s",
				__func__, ly_errmsg(ly_native_ctx));
		return false;
	}

	hiredis_data_tree_from_dnode(dnode_final, lyd_format, with_defaults);					  
						  
	yang_dnode_free(dnode_final);

	return true;
}

static bool hiredis_get_changes_iter(const char *str, LYD_FORMAT format, hi_change_iter_t **it)
{
	struct lyd_node *data = NULL;	
    int parse_flags;
	struct ly_in *in = NULL;

	assert(it);

	*it = calloc(1, sizeof **it);
	
	ly_in_new_memory(str, &in);
	
	parse_flags = LYD_PARSE_NO_STATE | LYD_PARSE_ONLY;

	if (lyd_parse_data(ly_native_ctx, NULL, in, format, parse_flags, 0, &data)) {

		zlog_err("parse data failure");
		return NULL;
	}

	if (lyd_find_xpath(data, "//*", &(*it)->set)) {

		zlog_err("search xpath filure");
		return false;
	}

	ly_in_free(in, true);
	(*it)->diff = data;
#if 0	
	lyd_free_all(data);
#endif
	return true;
}

static void hiredis_edit_diff_get_origin(const struct lyd_node *node, char **origin, int *origin_own)
{
    struct lyd_meta *meta = NULL, *attr_meta = NULL;
    struct lyd_attr *a;
    const struct lyd_node *parent;
    LY_ERR lyrc;

    *origin = NULL;
    if (origin_own) {
        *origin_own = 0;
    }

    for (parent = node; parent; parent = lyd_parent(parent)) {
        if (parent->schema) {
            meta = lyd_find_meta(parent->meta, NULL, "ietf-origin:origin");
            if (meta) {
                break;
            }
        } else {
            LY_LIST_FOR(((struct lyd_node_opaq *)parent)->attr, a) {
                /* try to parse into metadata */
                if (!strcmp(a->name.name, "origin")) {
                    lyrc = lyd_new_meta2(LYD_CTX(node), NULL, 0, a, &attr_meta);
                    if (lyrc && (lyrc != LY_ENOT)) {
                        return;
                    }
                    if (!lyrc) {
                        if (!strcmp(attr_meta->annotation->module->name, "ietf-origin")) {
                            meta = attr_meta;
                            break;
                        } else {
                            lyd_free_meta_single(attr_meta);
                            attr_meta = NULL;
                        }
                    }
                }
            }
        }
    }

    if (meta) {
        *origin = strdup(lyd_get_meta_value(meta));
        if (origin_own && (parent == node)) {
            *origin_own = 1;
        }
    }
    lyd_free_meta_single(attr_meta);
}

static bool hiredis_val_ly2sr(const struct lyd_node *node, hi_val_t *sr_val)
{
    char *ptr, *origin;
	int basetype;
    const struct lyd_node_term *leaf;
    const struct lyd_value *val;
    struct lyd_node_any *any;
    struct lyd_node *tree;

    sr_val->xpath = lyd_path(node, LYD_PATH_STD, NULL, 0);

	if (!sr_val->xpath)
		goto error;

    sr_val->dflt = node->flags & LYD_DEFAULT ? 1 : 0;

    switch (node->schema->nodetype) {
    case LYS_LEAF:
    case LYS_LEAFLIST:
        leaf = (const struct lyd_node_term *)node;
        val = &leaf->value;
store_value:
		basetype = val->realtype->basetype;
        switch (basetype) {
        case LY_TYPE_BINARY:
            sr_val->type = HI_BINARY_T;
            sr_val->data.binary_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));

			if (!sr_val->data.binary_val)
				goto error;
            break;
        case LY_TYPE_BITS:
            sr_val->type = HI_BITS_T;
            sr_val->data.bits_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
		
			if (!sr_val->data.bits_val)
				goto error;
            break;
        case LY_TYPE_BOOL:
            sr_val->type = HI_BOOL_T;
            sr_val->data.bool_val = val->boolean ? 1 : 0;
		
            break;
        case LY_TYPE_DEC64:
            sr_val->type = HI_DECIMAL64_T;
            sr_val->data.decimal64_val = strtod(lyd_value_get_canonical(LYD_CTX(node), val), &ptr);
            if (ptr[0]) {
                
                goto error;
            }
            break;
        case LY_TYPE_EMPTY:
            sr_val->type = HI_LEAF_EMPTY_T;
            sr_val->data.string_val = NULL;
            break;
        case LY_TYPE_ENUM:
            sr_val->type = HI_ENUM_T;
            sr_val->data.enum_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
            // SR_CHECK_MEM_GOTO(!sr_val->data.enum_val, err_info, error);
            break;
        case LY_TYPE_IDENT:
            sr_val->type = HI_IDENTITYREF_T;
            sr_val->data.identityref_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
            // SR_CHECK_MEM_GOTO(!sr_val->data.identityref_val, err_info, error);
            break;
        case LY_TYPE_INST:
            sr_val->type = HI_INSTANCEID_T;
            sr_val->data.instanceid_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
            // SR_CHECK_MEM_GOTO(!sr_val->data.instanceid_val, err_info, error);
            break;
        case LY_TYPE_INT8:
            sr_val->type = HI_INT8_T;
            sr_val->data.int8_val = val->int8;
            break;
        case LY_TYPE_INT16:
            sr_val->type = HI_INT16_T;
            sr_val->data.int16_val = val->int16;
            break;
        case LY_TYPE_INT32:
            sr_val->type = HI_INT32_T;
            sr_val->data.int32_val = val->int32;
            break;
        case LY_TYPE_INT64:
            sr_val->type = HI_INT64_T;
            sr_val->data.int64_val = val->int64;
            break;
        case LY_TYPE_STRING:
            sr_val->type = HI_STRING_T;
            sr_val->data.string_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));

			if (!sr_val->data.string_val)
				goto error;
            break;
        case LY_TYPE_UINT8:
            sr_val->type = HI_UINT8_T;
            sr_val->data.uint8_val = val->uint8;
            break;
        case LY_TYPE_UINT16:
            sr_val->type = HI_UINT16_T;
            sr_val->data.uint16_val = val->uint16;
            break;
        case LY_TYPE_UINT32:
            sr_val->type = HI_UINT32_T;
            sr_val->data.uint32_val = val->uint32;
            break;
        case LY_TYPE_UINT64:
            sr_val->type = HI_UINT64_T;
            sr_val->data.uint64_val = val->uint64;
            break;
        case LY_TYPE_UNION:
            val = &val->subvalue->value;
            goto store_value;
        default:
            return false;
        }
        break;
    case LYS_CONTAINER:
        if (node->schema->flags & LYS_PRESENCE) {
            sr_val->type = HI_CONTAINER_PRESENCE_T;
        } else {
            sr_val->type = HI_CONTAINER_T;
        }
        break;
    case LYS_LIST:
        sr_val->type = HI_LIST_T;
        break;
    case LYS_NOTIF:
        sr_val->type = HI_NOTIFICATION_T;
        break;
    case LYS_ANYXML:
    case LYS_ANYDATA:
        any = (struct lyd_node_any *)node;
        ptr = NULL;

        switch (any->value_type) {
        case LYD_ANYDATA_STRING:
        case LYD_ANYDATA_XML:
        case LYD_ANYDATA_JSON:
            if (any->value.str) {
                ptr = strdup(any->value.str);
                // SR_CHECK_MEM_RET(!ptr, err_info);
            }
            break;
        case LYD_ANYDATA_LYB:
            /* try to convert into a data tree */
            if (lyd_parse_data_mem(LYD_CTX(node), any->value.mem, LYD_LYB, LYD_PARSE_STRICT, 0, &tree)) {

				zlog_debug("Failed to convert LYB anyxml/anydata into XML.");
                return false;
            }
            free(any->value.mem);
            any->value_type = LYD_ANYDATA_DATATREE;
            any->value.tree = tree;
        /* fallthrough */
        case LYD_ANYDATA_DATATREE:
            lyd_print_mem(&ptr, any->value.tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
            break;
        }

        if (node->schema->nodetype == LYS_ANYXML) {
            sr_val->type = HI_ANYXML_T;
            sr_val->data.anyxml_val = ptr;
        } else {
            sr_val->type = HI_ANYDATA_T;
            sr_val->data.anydata_val = ptr;
        }
        break;
    default:
        return false;
    }

    /* origin */
    hiredis_edit_diff_get_origin(node, &origin, NULL);
    sr_val->origin = origin;

    return NULL;

error:
    free(sr_val->xpath);
    return false;
}

static void * hiredis_realloc(void *ptr, size_t size)
{
    void *new_mem;

    new_mem = realloc(ptr, size);
    if (!new_mem) {
        free(ptr);
    }

    return new_mem;
}

static bool hiredis_change_ly2sr(const struct lyd_node *node, const char *value_str,
	const char *anchor, hi_val_t **sr_val_p)
{
    uint32_t end;
    hi_val_t *sr_val;
    struct lyd_node *node_dup = NULL;
    const struct lyd_node *node_ptr;
    LY_ERR lyrc;

    sr_val = calloc(1, sizeof *sr_val);

    if (value_str) {
        /* replace the value in a node copy so that this specific one is stored */
        assert(node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST));
        lyrc = lyd_dup_single(node, NULL, 0, &node_dup);
        if (lyrc) {
            goto cleanup;
        }

        lyrc = lyd_change_term(node_dup, value_str);
        if (lyrc && (lyrc != LY_EEXIST) && (lyrc != LY_ENOT)) {            
            goto cleanup;
        }
        node_dup->parent = node->parent;
        node_dup->flags |= node->flags & LYD_DEFAULT;

        node_ptr = node_dup;
    } else {
        node_ptr = node;
    }

    /* fill the sr value */
#if 0	
    if ((!hiredis_val_ly2sr(node_ptr, sr_val))) {
        goto cleanup;
    }
#endif
	hiredis_val_ly2sr(node_ptr, sr_val);

    /* adjust specific members for changes */
    if (lysc_is_dup_inst_list(node->schema)) {
        /* fix the xpath if needed */
        if (anchor) {
            /* get xpath without the predicate */
            free(sr_val->xpath);
            sr_val->xpath = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);

			if (!sr_val->xpath)
				goto cleanup;

            end = strlen(sr_val->xpath);

            /* original length + '[' + anchor + ']' + ending 0 */
            sr_val->xpath = hiredis_realloc(sr_val->xpath, end + 1 + strlen(anchor) + 2);

			if (!sr_val->xpath)
				goto cleanup;

            /* concatenate the specific predicate */
            sprintf(sr_val->xpath + end, "[%s]", anchor);
        }
    } else if (node->schema->nodetype == LYS_LIST) {
        /* fix the xpath if needed */
        if (anchor) {
            /* get xpath without the keys predicate */
            free(sr_val->xpath);
            sr_val->xpath = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);

			if (!sr_val->xpath)
				goto cleanup;			

            end = strlen(sr_val->xpath);

            /* original length + anchor + ending 0 */
            sr_val->xpath = hiredis_realloc(sr_val->xpath, end + strlen(anchor) + 1);
			
			if (!sr_val->xpath)
				goto cleanup;

            /* concatenate the specific predicate */
            strcpy(sr_val->xpath + end, anchor);
        }
    } else if (node->schema->nodetype == LYS_LEAFLIST) {
        /* do not include the value predicate */
        free(sr_val->xpath);
        sr_val->xpath = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);

		if (!sr_val->xpath)
			goto cleanup;		
    } else if (node->schema->nodetype & LYS_ANYDATA) {
        /* TODO */
    }

	*sr_val_p = sr_val;
	return true;
cleanup:
    lyd_free_tree(node_dup);
    if (sr_val) {
        free(sr_val->xpath);
    }
    free(sr_val);

    return false;
}


static bool hiredis_set_getnext(struct ly_set *set, uint32_t *idx, 
	struct lyd_node **node)
{
	assert(set && idx && node);

    while (*idx < set->count) {
        *node = set->dnodes[*idx];

        /* success */
        ++(*idx);
        return true;
    }

    /* no more changes */
    *node = NULL;
    return false;
}

static bool hiredis_get_change_next(hi_change_iter_t *iter, hi_change_oper_t operation,
	hi_val_t **old_value, hi_val_t **new_value)
{
    // struct lyd_meta *meta, *meta2;
    struct lyd_node *node = NULL;
    // const char *meta_name;
    int op = operation;

    assert(iter && old_value && new_value);

	if (!hiredis_set_getnext(iter->set, &iter->idx, &node))
		return false;

	if (!node)
		return false;

    /* create values */
    switch (op) {
    case HI_OP_DELETED:
        if (!hiredis_change_ly2sr(node, NULL, NULL, old_value)) {
            return false;
        }
        *new_value = NULL;
        break;
    case HI_OP_MODIFIED:
#if 0		
        /* "orig-value" metadata contains the previous value */
        meta = lyd_find_meta(node->meta, NULL, "yang:orig-value");

        /* "orig-default" holds the previous default flag value */
        meta2 = lyd_find_meta(node->meta, NULL, "yang:orig-default");

        if (!meta || !meta2) {
            return false;
        }
		
        if (!hiredis_change_ly2sr(node, lyd_get_meta_value(meta), NULL, old_value)) {
            return false;
        }
        if (meta2->value.boolean) {
            (*old_value)->dflt = 1;
        } else {
            (*old_value)->dflt = 0;
        }
#endif		
        if (!hiredis_change_ly2sr(node, NULL, NULL, new_value)) {
            return false;
        }
		*old_value = NULL;
        break;
    case HI_OP_CREATED:
        if (!lysc_is_userordered(node->schema)) {
            /* not a user-ordered list, so the operation is a simple creation */
            *old_value = NULL;
            if (!hiredis_change_ly2sr(node, NULL, NULL, new_value)) {
                return false;
            }
            break;
        }
    /* fallthrough */
    case HI_OP_MOVED:
#if 0		
        if (lysc_is_dup_inst_list(node->schema)) {
            meta_name = "yang:position";
        } else if (node->schema->nodetype == LYS_LEAFLIST) {
            meta_name = "yang:value";
        } else {
            assert(node->schema->nodetype == LYS_LIST);
            meta_name = "yang:key";
        }
        /* attribute contains the value of the node before in the order */
        meta = lyd_find_meta(node->meta, NULL, meta_name);
        if (!meta) {
            return false;
        }

        if (lyd_get_meta_value(meta)[0]) {
            if (lysc_is_dup_inst_list(node->schema)) {
               	ret = hiredis_change_ly2sr(node, NULL, lyd_get_meta_value(meta), old_value);
            } else if (node->schema->nodetype == LYS_LEAFLIST) {
            	ret = hiredis_change_ly2sr(node, lyd_get_meta_value(meta), NULL, old_value);
            } else {
                ret = hiredis_change_ly2sr(node, NULL, lyd_get_meta_value(meta), old_value);
            }
            if (!ret) {
                return false;
            }
        } else {
            /* inserted as the first item */
            *old_value = NULL;
        }
#endif		
        if (!hiredis_change_ly2sr(node, NULL, NULL, new_value)) {
            return false;
        }
        break;
    }

    return true;
}

static int hiredis_val_to_buff(const hi_val_t *value, char buffer[], size_t size)
{
    size_t len = 0;
	int type;

    if (NULL == value) {
        return 0;
    }

	type = value->type;
    switch (type) {
    case HI_BINARY_T:
        if (NULL != value->data.binary_val) {
            len = snprintf(buffer, size, "%s", value->data.binary_val);
        }
        break;
    case HI_BITS_T:
        if (NULL != value->data.bits_val) {
            len = snprintf(buffer, size, "%s", value->data.bits_val);
        }
        break;
    case HI_BOOL_T:
        len = snprintf(buffer, size, "%s", value->data.bool_val ? "true" : "false");
        break;
    case HI_DECIMAL64_T:
        len = snprintf(buffer, size, "%g", value->data.decimal64_val);
        break;
    case HI_ENUM_T:
        if (NULL != value->data.enum_val) {
            len = snprintf(buffer, size, "%s", value->data.enum_val);
        }
        break;
    case HI_LIST_T:
    case HI_CONTAINER_T:
    case HI_CONTAINER_PRESENCE_T:
    case HI_LEAF_EMPTY_T:
        len = snprintf(buffer, size, "%s", "");
        break;
    case HI_IDENTITYREF_T:
        if (NULL != value->data.identityref_val) {
            len = snprintf(buffer, size, "%s", value->data.identityref_val);
        }
        break;
    case HI_INSTANCEID_T:
        if (NULL != value->data.instanceid_val) {
            len = snprintf(buffer, size, "%s", value->data.instanceid_val);
        }
        break;
    case HI_INT8_T:
        len = snprintf(buffer, size, "%" PRId8, value->data.int8_val);
        break;
    case HI_INT16_T:
        len = snprintf(buffer, size, "%" PRId16, value->data.int16_val);
        break;
    case HI_INT32_T:
        len = snprintf(buffer, size, "%" PRId32, value->data.int32_val);
        break;
    case HI_INT64_T:
        len = snprintf(buffer, size, "%" PRId64, value->data.int64_val);
        break;
    case HI_STRING_T:
        if (NULL != value->data.string_val) {
            len = snprintf(buffer, size, "%s", value->data.string_val);
        }
        break;
    case HI_UINT8_T:
        len = snprintf(buffer, size, "%" PRIu8, value->data.uint8_val);
        break;
    case HI_UINT16_T:
        len = snprintf(buffer, size, "%" PRIu16, value->data.uint16_val);
        break;
    case HI_UINT32_T:
        len = snprintf(buffer, size, "%" PRIu32, value->data.uint32_val);
        break;
    case HI_UINT64_T:
        len = snprintf(buffer, size, "%" PRIu64, value->data.uint64_val);
        break;
    case HI_ANYXML_T:
        if (NULL != value->data.anyxml_val) {
            len = snprintf(buffer, size, "%s", value->data.anyxml_val);
        }
        break;
    case HI_ANYDATA_T:
        if (NULL != value->data.anydata_val) {
            len = snprintf(buffer, size, "%s", value->data.anydata_val);
        }
        break;
    default:
        break;
    }

    return len;
}

static int frr_hiredis_process_change(struct nb_config *candidate,
	 hi_change_oper_t sr_op, hi_val_t *sr_old_val,
	 hi_val_t *sr_new_val)
{
	struct nb_node *nb_node;
	enum nb_operation nb_op;
	hi_val_t *sr_data;
	const char *xpath;
	char value_str[YANG_VALUE_MAXLEN];
	struct yang_data *data;
	int ret, op;

	sr_data = sr_new_val ? sr_new_val : sr_old_val;
	assert(sr_data);

	xpath = sr_data->xpath;

	DEBUGD(&nb_dbg_client_hiredis, "hiredis: processing change [xpath %s]",
	       xpath);

	/* Non-presence container - nothing to do. */
	if (sr_data->type == HI_CONTAINER_T)
		return NB_OK;

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		return NB_ERR;
	}

	/* Map operation values. */
	op = sr_op;
	switch (op) {
	case HI_OP_CREATED:
		nb_op = NB_OP_CREATE;
		break;
	case HI_OP_MODIFIED:
		if (nb_is_operation_allowed(nb_node, NB_OP_MODIFY))
			nb_op = NB_OP_MODIFY;
		else
			/* Ignore list keys modifications. */
			return NB_OK;
		break;
	case HI_OP_DELETED:

		if (!nb_is_operation_allowed(nb_node, NB_OP_DESTROY))
			return NB_OK;

		nb_op = NB_OP_DESTROY;
		break;
	case HI_OP_MOVED:
		nb_op = NB_OP_MOVE;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT,
			 "%s: unexpected operation %u [xpath %s]", __func__,
			 sr_op, xpath);
		return NB_ERR;
	}

	hiredis_val_to_buff(sr_data, value_str, sizeof(value_str));

	zlog_debug("xpath: %s, value: %s", xpath, value_str);

	data = yang_data_new(xpath, value_str);

	ret = nb_candidate_edit(candidate, nb_node, nb_op, xpath, NULL, data);
	yang_data_free(data);

	if (ret != NB_OK) {
		flog_warn(
			EC_LIB_NB_CANDIDATE_EDIT_ERROR,
			"%s: failed to edit candidate configuration: operation [%s] xpath [%s]",
			__func__, nb_operation_name(nb_op), xpath);
		return NB_ERR;
	}

	return NB_OK;
}

static bool hiredis_config_change(const char *str, LYD_FORMAT format, hi_change_oper_t op)
{
	bool ret;
	hi_change_iter_t* it;
	struct nb_config *candidate;
	hi_val_t *sr_old_val, *sr_new_val;

	if (!hiredis_get_changes_iter(str, format, &it))
		return false;

	candidate = nb_config_dup(running_config);

	while (hiredis_get_change_next(it, op, &sr_old_val, &sr_new_val)) {
		
		ret = frr_hiredis_process_change(candidate, op, sr_old_val, sr_new_val);
		
		hiredis_free_val(sr_old_val);
		hiredis_free_val(sr_new_val);
		if (ret != NB_OK)
			break;		
	}

	hiredis_free_change_iter(it);

	return frr_hiredis_change_apply(candidate);
}

static bool frr_hiredis_change_apply(struct nb_config *candidate)
{	
	struct nb_context context = {};	
	char errmsg[BUFSIZ] = {0};
	
	int ret;

	transaction = NULL;
	context.client = NB_CLIENT_HIREDIS;

	ret = nb_candidate_commit_prepare(context, candidate, NULL,
					  &transaction, false, false, errmsg,
					  sizeof(errmsg));	

	if (!transaction)
		nb_config_free(candidate);

	/* commit status */
	if (transaction) {
		struct nb_config *can = transaction->config;
		char errmsg[BUFSIZ] = {0};

		nb_candidate_commit_apply(transaction, true, NULL, errmsg,
					  sizeof(errmsg));
		nb_config_free(can);
	}	

	return ret? false: true;	

}
	
/* ******************************* xpath function end   ******************************************** */

/* ******************************* nb function wrapper start *************************************** */
static LY_ERR hiredis_data_tree_from_dnode(const struct lyd_node *dnode,
	LYD_FORMAT lyd_format, bool with_defaults)
{
	char *strp;
	int options = 0;

	SET_FLAG(options, LYD_PRINT_WITHSIBLINGS);
	if (with_defaults)
		SET_FLAG(options, LYD_PRINT_WD_ALL);
	else
		SET_FLAG(options, LYD_PRINT_WD_TRIM);

	LY_ERR err = lyd_print_mem(&strp, dnode, lyd_format, options);
	if (err == LY_SUCCESS) {

		zlog_debug("strp: %s", strp);
		printf("strp: %s\n", strp);
		free(strp);
	}
	return err;
}

static struct lyd_node *hiredis_get_dnode_config(const char *xpath)
{
	struct lyd_node *dnode;

	if (!xpath)
		return NULL;

	if (!yang_dnode_exists(running_config->dnode, xpath))
		return NULL;

	dnode = yang_dnode_get(running_config->dnode, xpath);
	if (dnode)
		dnode = yang_dnode_dup(dnode);

	return dnode;
}

static struct lyd_node *hiredis_get_dnode_state(const char *xpath)
{
	struct lyd_node *dnode = NULL;

	(void)nb_oper_iterate_legacy(xpath, NULL, 0, NULL, NULL, &dnode);

	return dnode;
}

/* ******************************* nb function wrapper end   *************************************** */

/* ******************************* daemon function start **************************************** */

static void hiredis_match_event(struct event *event)
{	
	char *str = EVENT_ARG(event);

	if (!str)
		return;

	hi_change_oper_t operation;
	if (hiredis_get_operation(str, &operation)) {

		hiredis_config_change(XSTRDUP(MTYPE_HIREDIS, str + strlen(hi_change_oper_str[operation]) + 1),
							   LYD_JSON, operation);
		XFREE(MTYPE_HIREDIS, str);
	}

}

static bool frr_daemon_sub_channel(const char *daemon_name)
{
	int i, j;

	if (!daemon_name)
		return false;	

	i = 0;
	while (hiredis_sub_channels[i][0]) {
		if (strncasecmp(daemon_name, hiredis_sub_channels[i][0],
				strlen(hiredis_sub_channels[i][0])) == 0)
			break;
		i++;
	}

	if (!hiredis_sub_channels[i][0]) {

		zlog_err("%s daemon not exists", daemon_name);
		return false;
	}

	j = 1;
	while (j < MAXIMUM_CHANNEL_NUM && hiredis_sub_channels[i][j]) {

 		hiredis_uv_subscribe(hiredis_sub_channels[i][j]);
		j++;
	}

	if (j == 1) {
		
		zlog_debug("%s not has any optional channels", daemon_name);		
	}

	return true;
}
/* ******************************* daemon function end   **************************************** */

static void hiredis_uv_subscribe(const char *channel)
{
	uint32_t channel_len;
	char *channel_str;

	if (!channel)
		return;

	channel_len = strlen(channel) + strlen("SUBSCRIBE") + 2;
	channel_str = XCALLOC(MTYPE_HIREDIS, channel_len);
	snprintf(channel_str, channel_len, "%s %s", "SUBSCRIBE", channel);
	
	redisAsyncCommand(hm->uv_context, hiredis_uv_cb, NULL, channel_str);

	XFREE(MTYPE_HIREDIS, channel_str);
}

static bool hiredis_uv_connect(void)
{
	hm->uv_loop = uv_default_loop();

	hm->uv_context = redisAsyncConnect("localhost", hm->port);
    if (hm->uv_context->err) {
		
		zlog_err("asyn connect to redis: %s", hm->uv_context->errstr);
        return false;
    }

	redisLibuvAttach(hm->uv_context, hm->uv_loop);
    redisAsyncSetConnectCallback(hm->uv_context, hiredis_uv_connect_cb);
    redisAsyncSetDisconnectCallback(hm->uv_context, hiredis_uv_disconnect_cb);

	frr_daemon_sub_channel(frr_protoname);

	uv_run(hm->uv_loop, UV_RUN_DEFAULT);

	return true;
}

static void hiredis_uv_cb(redisAsyncContext *c, void *reply, void *privdata)
{
    redisReply *r = reply;
	
    if (!reply) 
		return;

	if (r->type == REDIS_REPLY_ARRAY && r->elements == 3) {

		/*
		 * msg type: r->element[0]
		 * tun name: r->element[1]
		 * msg data: r->element[2]
		 */
		zlog_debug("subscribe channel: %s, msg: %s", r->element[0]->str, r->element[2]->str);

		event_add_event(master, hiredis_match_event, XSTRDUP(MTYPE_HIREDIS, r->element[2]->str), 0/*default none*/, &hm->event);
	}
}

static void hiredis_uv_connect_cb(const redisAsyncContext *c, int status)
{
    if (status != REDIS_OK) {

		flog_err(EC_LIB_HIREDIS_INIT, "%s: asyn connect error %s", __func__, c->errstr);
        return;
    }

	zlog_debug("hiredis asynchronized connects to redis");
}

static void hiredis_uv_disconnect_cb(const redisAsyncContext *c, int status)
{
    if (status != REDIS_OK) {

		flog_err(EC_LIB_HIREDIS_INIT, "%s: asyn disconnect error %s", __func__, c->errstr);
        return;
    }

	zlog_debug("hiredis asynchronized disconnects to redis");
}

static void *hiredis_pthread_start(void *arg)
{
	struct frr_pthread *fpt = (struct frr_pthread *)arg;

	/*
	 * We are not using normal FRR pthread mechanics and are
	 * not using fpt_run
	 */
	frr_pthread_set_name(fpt);

#ifdef HAVE_UV
	hiredis_uv_connect();
#endif

	return NULL;
}

static int frr_hiredis_init(void)
{
	int ret = -1;
	
	struct frr_pthread_attr attr = {
		.start = hiredis_pthread_start,
		.stop = NULL,
	};

	zlog_debug("%s enter", __FUNCTION__);

	fpt = frr_pthread_new(&attr, "frr-redis", "frr-redis");

	/* Create a pthread for hIREDIS since it runs its own event loop. */
	if (frr_pthread_run(fpt, NULL) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL, "%s: error creating pthread: %s",
			 __FUNCTION__, safe_strerror(errno));
		return ret;
	}

	return 0;
}

static int frr_hiredis_finish(void)
{
	if (!fpt)
		return 0;
		
	if (!hm->context)
	    redisFree(hm->context);	

	if (!hm->uv_context) {
		redisAsyncDisconnect(hm->uv_context);
		free(hm->uv_context);
	}	

	// pthread_join(fpt->thread, NULL);
	frr_pthread_destroy(fpt);

	return 0;
}

static void frr_hiredis_module_very_late_init(struct event *thread)
{
	const char *args = THIS_MODULE->load_args;
	uint64_t port = HIREDIS_DEFAULT_PORT;

	if (args) {
		port = atoi(args);
		if (port < 1024 || port > UINT16_MAX) {
			flog_err(EC_LIB_HIREDIS_INIT,
				 "%s: port number must be between 1025 and %d",
				 __func__, UINT16_MAX);
			goto error;
		}
	}

	hm->port = port;

	if (frr_hiredis_init() < 0)
		goto error;

	return;

error:
	flog_err(EC_LIB_HIREDIS_INIT, "failed to initialize the hiredis module");
}


static int frr_hiredis_module_late_init(struct event_loop *tm)
{
	master = tm;

	hook_register(frr_fini, frr_hiredis_finish);
	frr_hiredis_cli_init();
	event_add_event(tm, frr_hiredis_module_very_late_init, NULL, 0, NULL);	

	return 0;
}

static int frr_hiredis_module_init(void)
{
	hook_register(frr_late_init, frr_hiredis_module_late_init);

	return 0;
}

FRR_MODULE_SETUP(.name = "frr_hiredis", .version = FRR_VERSION,
		 .description = "FRR hiredis northbound module",
		 .init = frr_hiredis_module_init,
);
