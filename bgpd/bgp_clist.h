// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Community list.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_CLIST_H
#define _QUAGGA_BGP_CLIST_H

#include "jhash.h"

/* Master Community-list. */
#define COMMUNITY_LIST_MASTER          0
#define EXTCOMMUNITY_LIST_MASTER       1
#define LARGE_COMMUNITY_LIST_MASTER    2

/* Community-list deny and permit.  */
#define COMMUNITY_DENY                 0
#define COMMUNITY_PERMIT               1

/* Number and string based community-list name.  */
#define COMMUNITY_LIST_STRING          0
#define COMMUNITY_LIST_NUMBER          1
/* The numbered community-list (including large/ext communities)
 * have a range between 1-500.
 */
#define COMMUNITY_LIST_NUMBER_MAX 500

#define COMMUNITY_SEQ_NUMBER_AUTO     -1

/* Community-list entry types.  */
#define COMMUNITY_LIST_STANDARD        0 /* Standard community-list.  */
#define COMMUNITY_LIST_EXPANDED        1 /* Expanded community-list.  */
#define EXTCOMMUNITY_LIST_STANDARD     2 /* Standard extcommunity-list.  */
#define EXTCOMMUNITY_LIST_EXPANDED     3 /* Expanded extcommunity-list.  */
#define LARGE_COMMUNITY_LIST_STANDARD  4 /* Standard Large community-list.  */
#define LARGE_COMMUNITY_LIST_EXPANDED  5 /* Expanded Large community-list.  */

/* Community-list.  */
struct community_list {
	/* Name of the community-list.  */
	char *name;

	/* Stored hash value of name, to further speed up hash operations */
	uint32_t name_hash;

	/* String or number.  */
	int sort;

	/* Link to upper list.  */
	struct community_list_list *parent;

	/* Linked list for other community-list.  */
	struct community_list *next;
	struct community_list *prev;

	/* Community-list entry in this community-list.  */
	struct community_entry *head;
	struct community_entry *tail;
};

/* Each entry in community-list.  */
struct community_entry {
	struct community_entry *next;
	struct community_entry *prev;

	/* Permit or deny.  */
	uint8_t direct;

	/* Standard or expanded.  */
	uint8_t style;

	/* Sequence number. */
	int64_t seq;

	/* Community structure.  */
	union {
		struct community *com;
		struct ecommunity *ecom;
		struct lcommunity *lcom;
	} u;

	/* Configuration string.  */
	char *config;

	/* Expanded community-list regular expression.  */
	regex_t *reg;
};

/* Linked list of community-list.  */
struct community_list_list {
	struct community_list *head;
	struct community_list *tail;
};

/* Master structure of community-list and extcommunity-list.  */
struct community_list_master {
	struct community_list_list num;
	struct community_list_list str;
	struct hash *hash;
};

/* Community-list handler.  community_list_init() returns this
   structure as handler.  */
struct community_list_handler {
	/* Community-list.  */
	struct community_list_master community_list;

	/* Exteded community-list.  */
	struct community_list_master extcommunity_list;

	/* Large community-list.  */
	struct community_list_master lcommunity_list;
};

/* Error code of community-list.  */
#define COMMUNITY_LIST_ERR_MALFORMED_VAL     -1
#define COMMUNITY_LIST_ERR_STANDARD_CONFLICT -2
#define COMMUNITY_LIST_ERR_EXPANDED_CONFLICT -3
/* Handler.  */
extern struct community_list_handler *bgp_clist;

/* Prototypes.  */
extern struct community_list_handler *community_list_init(void);
extern void community_list_terminate(struct community_list_handler *ch);

extern int community_list_set(struct community_list_handler *ch,
			      const char *name, const char *str,
			      const char *seq, int direct, int style);
extern void community_list_unset(struct community_list_handler *ch,
				 const char *name, const char *str,
				 const char *seq, int direct, int style);
extern int extcommunity_list_set(struct community_list_handler *ch,
				 const char *name, const char *str,
				 const char *seq, int direct, int style);
extern void extcommunity_list_unset(struct community_list_handler *ch,
				    const char *name, const char *str,
				    const char *seq, int direct, int style);
extern int lcommunity_list_set(struct community_list_handler *ch,
			       const char *name, const char *str,
			       const char *seq, int direct, int style);
extern bool lcommunity_list_valid(const char *community, int style);
extern void lcommunity_list_unset(struct community_list_handler *ch,
				  const char *name, const char *str,
				  const char *seq, int direct, int style);

extern struct community_list_master *
community_list_master_lookup(struct community_list_handler *ch, int master);

extern struct community_list *
community_list_lookup(struct community_list_handler *c, const char *name,
		      uint32_t name_hash, int master);

extern bool community_list_match(struct community *com,
				 struct community_list *list);
extern bool ecommunity_list_match(struct ecommunity *ecom,
				  struct community_list *list);
extern bool lcommunity_list_match(struct lcommunity *lcom,
				  struct community_list *list);
extern bool community_list_exact_match(struct community *com,
				       struct community_list *list);
extern bool lcommunity_list_exact_match(struct lcommunity *lcom,
					struct community_list *list);
extern bool community_list_any_match(struct community *com,
				     struct community_list *list);
extern struct community *
community_list_match_delete(struct community *com, struct community_list *list);
extern bool lcommunity_list_any_match(struct lcommunity *lcom,
				      struct community_list *list);
extern struct lcommunity *
lcommunity_list_match_delete(struct lcommunity *lcom,
			     struct community_list *list);
extern struct ecommunity *
ecommunity_list_match_delete(struct ecommunity *ecom,
			     struct community_list *list);

static inline uint32_t bgp_clist_hash_key(char *name)
{
	return jhash(name, strlen(name), 0xdeadbeaf);
}

extern void bgp_community_list_command_completion_setup(void);

#endif /* _QUAGGA_BGP_CLIST_H */
