/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _QOBJ_H
#define _QOBJ_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

/* reserve a specific amount of bytes for a struct, which can grow up to
 * that size (or be dummy'd out if not needed)
 *
 * note the padding's array size will be an error if it gets negative or zero;
 * this is intentional to prevent the struct from growing beyond the allocated
 * space.
 */
#define RESERVED_SPACE_STRUCT(name, fieldname, size)                           \
	struct {                                                               \
		struct name fieldname;                                         \
		char padding##fieldname[size - sizeof(struct name)];           \
	};

/* don't need struct definitions for these here.  code actually using
 * these needs to define the struct *before* including this header.
 * HAVE_QOBJ_xxx should be defined to +1 in that case, like this:
 *
 * #if defined(HAVE_QOBJ_NODETYPE_CLI) && HAVE_QOBJ_NODETYPE_CLI < 0
 * #error include files are in wrong order
 * #else
 * #define HAVE_QOBJ_NODETYPE_CLI 1
 * struct qobj_nodetype_cli { ... }
 * #endif
 */
#ifndef HAVE_QOBJ_NODETYPE_CLI
#define HAVE_QOBJ_NODETYPE_CLI -1
struct qobj_nodetype_cli {
	int dummy;
};
#endif

#ifndef HAVE_QOBJ_NODETYPE_CAPNP
#define HAVE_QOBJ_NODETYPE_CAPNP -1
struct qobj_nodetype_capnp {
	int dummy;
};
#endif

/* each different kind of object will have a global variable of this type,
 * which can be used by various other pieces to store type-related bits.
 * type equality can be tested as pointer equality. (cf. QOBJ_GET_TYPESAFE)
 */
struct qobj_nodetype {
	ptrdiff_t node_member_offset;
	RESERVED_SPACE_STRUCT(qobj_nodetype_cli, cli, 256)
	RESERVED_SPACE_STRUCT(qobj_nodetype_capnp, capnp, 256)
};

/* anchor to be embedded somewhere in the object's struct */
struct qobj_node {
	uint64_t nid;
	struct qobj_nodetype *type;
};

#define QOBJ_FIELDS struct qobj_node qobj_node;

/* call these at the end of any _create function (QOBJ_REG)
 * and beginning of any _destroy function (QOBJ_UNREG) */
#define QOBJ_REG(n, structname) qobj_reg(&n->qobj_node, &qobj_t_##structname)
#define QOBJ_UNREG(n) qobj_unreg(&n->qobj_node)

/* internals - should not be directly used without a good reason
 *
 * note: qobj_get is essentially never safe to use in MT context because
 * the object could be deleted by another thread -- and worse, it could be
 * of the "wrong" type and deleted.
 *
 * with qobj_get_typed, the type check is done under lock, which means that
 * it can be used as long as another lock prevents the deletion of objects
 * of the expected type.
 *
 * in the long this may need another touch, e.g. built-in per-object locking.
 */
void qobj_reg(struct qobj_node *node, struct qobj_nodetype *type);
void qobj_unreg(struct qobj_node *node);
struct qobj_node *qobj_get(uint64_t id);
void *qobj_get_typed(uint64_t id, struct qobj_nodetype *type);

/* type declarations */
#define DECLARE_QOBJ_TYPE(structname)                                          \
	extern struct qobj_nodetype qobj_t_##structname;
#define DEFINE_QOBJ_TYPE(structname)                                           \
	struct qobj_nodetype qobj_t_##structname = {                           \
		.node_member_offset =                                          \
			(ptrdiff_t)offsetof(struct structname, qobj_node)};
#define DEFINE_QOBJ_TYPE_INIT(structname, ...)                                 \
	struct qobj_nodetype qobj_t_##structname = {                           \
		.node_member_offset =                                          \
			(ptrdiff_t)offsetof(struct structname, qobj_node),     \
		__VA_ARGS__};

/* ID dereference with typecheck.
 * will return NULL if id not found or wrong type. */
#define QOBJ_GET_TYPESAFE(id, structname)                                      \
	((struct structname *)qobj_get_typed((id), &qobj_t_##structname))

#define QOBJ_ID(ptr) ((ptr)->qobj_node.nid)
#define QOBJ_ID_0SAFE(ptr)                                                     \
	({                                                                     \
		typeof(ptr) _ptr = (ptr);                                      \
		_ptr ? _ptr->qobj_node.nid : 0ULL;                             \
	})

void qobj_init(void);
void qobj_finish(void);

#endif /* _QOBJ_H */
