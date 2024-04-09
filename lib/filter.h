// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Route filtering function.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_FILTER_H
#define _ZEBRA_FILTER_H

#include "if.h"
#include "prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum ACL name length */
#define ACL_NAMSIZ                128

/** Cisco host wildcard mask. */
#define CISCO_HOST_WILDCARD_MASK  "0.0.0.0"
/** Cisco host wildcard binary mask. */
#define CISCO_BIN_HOST_WILDCARD_MASK INADDR_ANY

/** Cisco any wildcard mask. */
#define CISCO_ANY_WILDCARD_MASK   "255.255.255.255"
/** Cisco binary any wildcard mask. */
#define CISCO_BIN_ANY_WILDCARD_MASK INADDR_NONE

/* Filter direction.  */
#define FILTER_IN                 0
#define FILTER_OUT                1
#define FILTER_MAX                2

/* Filter type is made by `permit', `deny' and `dynamic'. */
enum filter_type { FILTER_DENY, FILTER_PERMIT, FILTER_DYNAMIC };

struct filter_cisco {
	/* Cisco access-list */
	int extended;
	struct in_addr addr;
	struct in_addr addr_mask;
	struct in_addr mask;
	struct in_addr mask_mask;
};

struct filter_zebra {
	/* If this filter is "exact" match then this flag is set. */
	int exact;

	/* Prefix information. */
	struct prefix prefix;
};

/* Forward declaration of access-list struct. */
struct access_list;

/* Filter element of access list */
struct filter {
	/* For doubly linked list. */
	struct filter *next;
	struct filter *prev;

	/* Parent access-list pointer. */
	struct access_list *acl;

	/* Filter type information. */
	enum filter_type type;

	/* Sequence number */
	int64_t seq;

	/* Cisco access-list */
	int cisco;

	union {
		struct filter_cisco cfilter;
		struct filter_zebra zfilter;
	} u;
};

/* Access list */
struct access_list {
	char *name;
	char *remark;

	struct access_master *master;

	struct access_list *next;
	struct access_list *prev;

	struct filter *head;
	struct filter *tail;
};

/* List of access_list. */
struct access_list_list {
	struct access_list *head;
	struct access_list *tail;
};

/* Master structure of access_list. */
struct access_master {
	/* List of access_list which name is string. */
	struct access_list_list str;

	/* Hook function which is executed when new access_list is added. */
	void (*add_hook)(struct access_list *);

	/* Hook function which is executed when access_list is deleted. */
	void (*delete_hook)(struct access_list *);
};


/* Prototypes for access-list. */
extern void access_list_init(void);
extern void access_list_init_new(bool in_backend);
extern void access_list_reset(void);
extern void access_list_add_hook(void (*func)(struct access_list *));
extern void access_list_delete_hook(void (*func)(struct access_list *));
extern struct access_list *access_list_lookup(afi_t, const char *);
extern enum filter_type access_list_apply(struct access_list *access,
					  const void *object);

struct access_list *access_list_get(afi_t afi, const char *name);
void access_list_delete(struct access_list *access);
struct filter *filter_new(void);
void access_list_filter_add(struct access_list *access, struct filter *filter);
void access_list_filter_delete(struct access_list *access,
			       struct filter *filter);
void access_list_filter_update(struct access_list *access);
int64_t filter_new_seq_get(struct access_list *access);

extern const struct frr_yang_module_info frr_filter_info;
extern const struct frr_yang_module_info frr_filter_cli_info;


/* filter_nb.c */
enum yang_access_list_type {
	YALT_IPV4 = 0,
	YALT_IPV6 = 1,
	YALT_MAC = 2,
};

enum yang_prefix_list_type {
	YPLT_IPV4 = 0,
	YPLT_IPV6 = 1,
};

enum yang_prefix_list_action {
	YPLA_DENY = 0,
	YPLA_PERMIT = 1,
};

struct acl_dup_args {
	/** Access list type ("ipv4", "ipv6" or "mac"). */
	const char *ada_type;
	/** Access list name. */
	const char *ada_name;

	/** Entry action. */
	const char *ada_action;

#define ADA_MAX_VALUES 4
	/** Entry XPath for value. */
	const char *ada_xpath[ADA_MAX_VALUES];
	/** Entry value to match. */
	const char *ada_value[ADA_MAX_VALUES];

	/** Duplicated entry found in list? */
	bool ada_found;

	/** Sequence number of the found entry */
	int64_t ada_seq;

	/** (Optional) Already existing `dnode`. */
	const struct lyd_node *ada_entry_dnode;
};

/**
 * Check for duplicated entries using the candidate configuration.
 *
 * \param vty so we can get the candidate config.
 * \param ada the arguments to check.
 */
bool acl_is_dup(const struct lyd_node *dnode, struct acl_dup_args *ada);

struct plist_dup_args {
	/** Access list type ("ipv4" or "ipv6"). */
	const char *pda_type;
	/** Access list name. */
	const char *pda_name;

	/** Entry action. */
	const char *pda_action;

	bool any;
	struct prefix prefix;
	int ge;
	int le;

	/** Duplicated entry found in list? */
	bool pda_found;

	/** Sequence number of the found entry */
	int64_t pda_seq;

	/** (Optional) Already existing `dnode`. */
	const struct lyd_node *pda_entry_dnode;
};

/**
 * Check for duplicated entries using the candidate configuration.
 *
 * \param vty so we can get the candidate config.
 * \param pda the arguments to check.
 */
bool plist_is_dup(const struct lyd_node *dnode, struct plist_dup_args *pda);

/* filter_cli.c */
struct lyd_node;
struct vty;

extern int access_list_cmp(const struct lyd_node *dnode1,
			   const struct lyd_node *dnode2);
extern void access_list_show(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults);
extern void access_list_remark_show(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
extern int prefix_list_cmp(const struct lyd_node *dnode1,
			   const struct lyd_node *dnode2);
extern void prefix_list_show(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults);
extern void prefix_list_remark_show(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);

void filter_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_FILTER_H */
