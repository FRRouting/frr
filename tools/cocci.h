/* some of this stuff doesn't seem to parse properly in coccinelle
 */

#define DEFUN(funcname, cmdname, str, help)                                    \
	static int funcname(const struct cmd_element *self, struct vty *vty,   \
			    int argc, struct cmd_token *argv[])
#define DEFUN_HIDDEN(funcname, cmdname, str, help)                             \
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
