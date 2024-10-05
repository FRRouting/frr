// SPDX-License-Identifier: GPL-2.0-or-later

/* some of this stuff doesn't seem to parse properly in coccinelle
 */

#define DEFUN(funcname, cmdname, str, help)                                    \
	static int funcname(const struct cmd_element *self, struct vty *vty,   \
			    int argc, struct cmd_token *argv[])
#define DEFUN_HIDDEN(funcname, cmdname, str, help)                             \
	static int funcname(const struct cmd_element *self, struct vty *vty,   \
			    int argc, struct cmd_token *argv[])
#define DEFUN_NOSH(funcname, cmdname, str, help)                               \
	static int funcname(const struct cmd_element *self, struct vty *vty,   \
			    int argc, struct cmd_token *argv[])
#define DEFPY(funcname, cmdname, str, help)                                    \
	static int funcname(const struct cmd_element *self, struct vty *vty,   \
			    int argc, struct cmd_token *argv[])
#define DEFPY_HIDDEN(funcname, cmdname, str, help)                             \
	static int funcname(const struct cmd_element *self, struct vty *vty,   \
			    int argc, struct cmd_token *argv[])
#define DEFPY_NOSH(funcname, cmdname, str, help)                               \
	static int funcname(const struct cmd_element *self, struct vty *vty,   \
			    int argc, struct cmd_token *argv[])

#define ENABLE_BGP_VNC 1
#define ALL_LIST_ELEMENTS_RO(list, node, data)                                 \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL && ((data) = listgetdata(node));                        \
	(node) = listnextnode(node), ((data) = NULL)
#define ALL_LIST_ELEMENTS(list, node, nextnode, data)                          \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL                                                         \
		&& ((data) = listgetdata(node), (nextnode) = node->next);      \
	(node) = (nextnode), ((data) = NULL)
#define LIST_HEAD(name, type)                                                  \
	struct name {                                                          \
		struct type *lh_first; /* first element */                     \
	}
#define LIST_ENTRY(type)                                                       \
	struct {                                                               \
		struct type *le_next;  /* next element */                      \
		struct type **le_prev; /* address of previous next element */  \
	}

#define STREAM_GETC(S, P)                                                      \
	do {                                                                   \
		uint8_t _pval;                                                 \
		if (!stream_getc2((S), &_pval))                                \
			goto stream_failure;                                   \
		(P) = _pval;                                                   \
	} while (0)

#define STREAM_GETW(S, P)                                                      \
	do {                                                                   \
		uint16_t _pval;                                                \
		if (!stream_getw2((S), &_pval))                                \
			goto stream_failure;                                   \
		(P) = _pval;                                                   \
	} while (0)

#define STREAM_GETL(S, P)                                                      \
	do {                                                                   \
		uint32_t _pval;                                                \
		if (!stream_getl2((S), &_pval))                                \
			goto stream_failure;                                   \
		(P) = _pval;                                                   \
	} while (0)

#define STREAM_GETF(S, P)                                                      \
	do {                                                                   \
		union {                                                        \
			float r;                                               \
			uint32_t d;                                            \
		} _pval;                                                       \
		if (stream_getl2((S), &_pval.d))                               \
			goto stream_failure;                                   \
		(P) = _pval.r;                                                 \
	} while (0)

#define STREAM_GETQ(S, P)                                                      \
	do {                                                                   \
		uint64_t _pval;                                                \
		if (!stream_getq2((S), &_pval))                                \
			goto stream_failure;                                   \
		(P) = _pval;                                                   \
	} while (0)

#define STREAM_GET(P, STR, SIZE)                                               \
	do {                                                                   \
		if (!stream_get2((P), (STR), (SIZE)))                          \
			goto stream_failure;                                   \
	} while (0)

#define AF_FOREACH(af) for ((af) = BGP_AF_START; (af) < BGP_AF_MAX; (af)++)

#define FOREACH_AFI_SAFI(afi, safi)                                            \
                                                                               \
	for (afi = AFI_IP; afi < AFI_MAX; afi++)                               \
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)

#define FOREACH_SAFI(safi) for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)

#define frr_with_privs(p) \
	for (int x = 1; x; x--)
#define frr_with_mutex(m) \
	for (int x = 1; x; x--)

#define ALL_LSDB_TYPED_ADVRTR(lsdb, type, adv_router, lsa)                     \
	const struct route_node *iterend =                                     \
		ospf6_lsdb_head(lsdb, 2, type, adv_router, &lsa);              \
	lsa;                                                                   \
	lsa = ospf6_lsdb_next(iterend, lsa)

#define ALL_LSDB_TYPED(lsdb, type, lsa)                                        \
	const struct route_node *iterend =                                     \
		ospf6_lsdb_head(lsdb, 1, type, 0, &lsa);                       \
	lsa;                                                                   \
	lsa = ospf6_lsdb_next(iterend, lsa)

#define ALL_LSDB(lsdb, lsa)                                                    \
	const struct route_node *iterend =                                     \
		ospf6_lsdb_head(lsdb, 0, 0, 0, &lsa);                          \
	lsa;                                                                   \
	lsa = ospf6_lsdb_next(iterend, lsa)

#define QOBJ_FIELDS struct qobj_node qobj_node;
