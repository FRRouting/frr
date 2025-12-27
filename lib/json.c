// SPDX-License-Identifier: GPL-2.0-or-later
/* json-c wrapper
 * Copyright (C) 2015 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "command.h"
#include "lib/json.h"
#include "json-c/printbuf.h"

/*
 * This function assumes that the json keyword
 * is the *last* keyword on the line no matter
 * what.
 */
bool use_json(const int argc, struct cmd_token *argv[])
{
	if (argc == 0)
		return false;

	if (argv[argc - 1]->arg && strmatch(argv[argc - 1]->text, "json"))
		return true;

	return false;
}

struct json_object *json_object_new_stringv(const char *fmt, va_list args)
{
	struct json_object *ret;
	char *text, buf[256];

	text = vasnprintfrr(MTYPE_TMP, buf, sizeof(buf), fmt, args);
	ret = json_object_new_string(text);

	if (text != buf)
		XFREE(MTYPE_TMP, text);
	return ret;
}

void json_array_string_add(json_object *json, const char *str)
{
	json_object_array_add(json, json_object_new_string(str));
}

void json_array_string_addv(json_object *json, const char *fmt, va_list args)
{
	json_object_array_add(json, json_object_new_stringv(fmt, args));
}

void json_object_string_add(struct json_object *obj, const char *key,
			    const char *s)
{
	json_object_object_add(obj, key, json_object_new_string(s));
}

void json_object_string_addv(struct json_object *obj, const char *key,
			     const char *fmt, va_list args)
{
	json_object_object_add(obj, key, json_object_new_stringv(fmt, args));
}

void json_object_object_addv(struct json_object *parent,
			     struct json_object *child, const char *keyfmt,
			     va_list args)
{
	char *text, buf[256];

	text = vasnprintfrr(MTYPE_TMP, buf, sizeof(buf), keyfmt, args);
	json_object_object_add(parent, text, child);

	if (text != buf)
		XFREE(MTYPE_TMP, text);
}

void json_object_int_add(struct json_object *obj, const char *key, int64_t i)
{
	json_object_object_add(obj, key, json_object_new_int64(i));
}

void json_object_double_add(struct json_object *obj, const char *key, double i)
{
	json_object_object_add(obj, key, json_object_new_double(i));
}

void json_object_boolean_false_add(struct json_object *obj, const char *key)
{
	json_object_object_add(obj, key, json_object_new_boolean(0));
}

void json_object_boolean_true_add(struct json_object *obj, const char *key)
{
	json_object_object_add(obj, key, json_object_new_boolean(1));
}

void json_object_boolean_add(struct json_object *obj, const char *key, bool val)
{
	json_object_object_add(obj, key, json_object_new_boolean(val));
}

struct json_object *json_object_lock(struct json_object *obj)
{
	return json_object_get(obj);
}

void json_object_free(struct json_object *obj)
{
	json_object_put(obj);
}

/*
 * Incremental json output support: depends on some apis that may not be present
 * in older libjson-c releases.
 */

#if JSON_C_MAJOR_VERSION > 0 || JSON_C_MINOR_VERSION > 12

/*
 * Flags values used in incremental json output
 */

/* Output of object has started; start-of-collection strings have been emitted */
#define FRR_JSON_STARTED   0x01
/* Object output is incomplete; don't emit end-of-collection strings yet */
#define FRR_JSON_OPEN      0x02
/* Object output has started, may need comma or separator */
#define FRR_JSON_COLLECTION  0x04
/* Object was OPEN, but is now complete; emit end-of-collection strings */
#define FRR_JSON_CLOSED      0x08

/* Helper to return json object userdata as flags int */
static int frr_json_get_flags(struct json_object *jobj)
{
	void *pflags;

	pflags = json_object_get_userdata(jobj);
	return (int)(intptr_t)pflags;
}

/*
 * Helper to set or update FRR userdata in a json object.
 */
static void frr_json_set_data(struct json_object *jobj, intptr_t iflags)
{
	void *flags = (void *)iflags;

	json_object_set_userdata(jobj, flags, NULL);
}

/* Helper to indent string output */
static void frr_json_indent(struct printbuf *pb, int level, int flags)
{
	if (flags & JSON_C_TO_STRING_PRETTY) {
		if (flags & JSON_C_TO_STRING_PRETTY_TAB)
			printbuf_memset(pb, -1, '\t', level);
		else
			printbuf_memset(pb, -1, ' ', level * 2);
	}
}

static const char *frr_json_hex_chars = "0123456789abcdefABCDEF";

/* Helper for string escaping */
static int frr_json_escape_str(struct printbuf *pb, const char *str, size_t len, int flags)
{
	size_t pos = 0, start_offset = 0;
	unsigned char c;

	while (len) {
		--len;
		c = str[pos];
		switch (c) {
		case '\b':
		case '\n':
		case '\r':
		case '\t':
		case '\f':
		case '"':
		case '\\':
		case '/':
			if ((flags & JSON_C_TO_STRING_NOSLASHESCAPE) && c == '/') {
				pos++;
				break;
			}

			if (pos > start_offset)
				printbuf_memappend(pb, str + start_offset, pos - start_offset);

			if (c == '\b')
				printbuf_memappend(pb, "\\b", 2);
			else if (c == '\n')
				printbuf_memappend(pb, "\\n", 2);
			else if (c == '\r')
				printbuf_memappend(pb, "\\r", 2);
			else if (c == '\t')
				printbuf_memappend(pb, "\\t", 2);
			else if (c == '\f')
				printbuf_memappend(pb, "\\f", 2);
			else if (c == '"')
				printbuf_memappend(pb, "\\\"", 2);
			else if (c == '\\')
				printbuf_memappend(pb, "\\\\", 2);
			else if (c == '/')
				printbuf_memappend(pb, "\\/", 2);

			start_offset = ++pos;
			break;
		default:
			if (c < ' ') {
				char sbuf[7];

				if (pos > start_offset)
					printbuf_memappend(pb, str + start_offset,
							   pos - start_offset);
				snprintf(sbuf, sizeof(sbuf), "\\u00%c%c",
					 frr_json_hex_chars[c >> 4],
					 frr_json_hex_chars[c & 0xf]);
				printbuf_memappend_fast(pb, sbuf, (int)sizeof(sbuf) - 1);
				start_offset = ++pos;
			} else {
				pos++;
			}
		}
	}
	if (pos > start_offset)
		printbuf_memappend(pb, str + start_offset, pos - start_offset);
	return 0;
}

/*
 * FRR custom json output for vty. Examine the children of 'jobj'.
 * Print singleton types and mark complete. Recurse into child collections
 * and determine whether the child is complete. If so, free/remove it; if
 * not, return.
 */
static int frr_json_obj_to_vty(struct vty *vty, struct json_object *jobj,
			       struct printbuf *pb, int level, int jflags)
{
	int parent_flags, child_flags;
	const char *key;
	size_t idx;
	struct json_object *jval;
	struct lh_table *lhtable;
	struct lh_entry *lhentry;
	bool children_p = false;
	enum json_type jtype;
	const char *str;
	bool pb_top = false;

	/* Check object's FRR flags */
	parent_flags = frr_json_get_flags(jobj);
	jtype = json_object_get_type(jobj);

	/* We only expect to be here for object/dict and array types */
	assert(jtype == json_type_object || jtype == json_type_array);

	/* At top-level we might need to allocate a buffer */
	if (pb == NULL) {
		pb = printbuf_new();
		pb_top = true;
	}

	/* If needed, emit the "start" json marker */
	if (!CHECK_FLAG(parent_flags, FRR_JSON_STARTED)) {
		if (jtype == json_type_array)
			printbuf_strappend(pb, "[");
		else if (jtype == json_type_object)
			printbuf_strappend(pb, "{" /*}*/);

		SET_FLAG(parent_flags, FRR_JSON_STARTED);
		frr_json_set_data(jobj, parent_flags);
	}

	/* Iterate through the children of 'jobj', output singletons,
	 * recurse into collections.
	 */
	if (jtype == json_type_object) {
		lhtable = json_object_get_object(jobj);
		lhentry = lhtable->head;
		while (lhentry) {
			jval = (struct json_object *)lh_entry_v(lhentry);
			key = (char *)lh_entry_k(lhentry);

			child_flags = frr_json_get_flags(jval);

			if (CHECK_FLAG(parent_flags, FRR_JSON_COLLECTION))
				children_p = true;

			/* Print key for new child */
			if (!CHECK_FLAG(child_flags, FRR_JSON_STARTED)) {
				if (children_p)
					printbuf_strappend(pb, ",");

				SET_FLAG(parent_flags, FRR_JSON_COLLECTION);
				frr_json_set_data(jobj, parent_flags);

				if (jflags & JSON_C_TO_STRING_PRETTY)
					printbuf_strappend(pb, "\n");
				if (jflags & JSON_C_TO_STRING_SPACED &&
				    !(jflags & JSON_C_TO_STRING_PRETTY))
					printbuf_strappend(pb, " ");

				frr_json_indent(pb, level + 1, jflags);

				printbuf_strappend(pb, "\"");
				frr_json_escape_str(pb, key, strlen(key), jflags);
				printbuf_strappend(pb, "\"");

				if (jflags & JSON_C_TO_STRING_SPACED)
					printbuf_strappend(pb, ": ");
				else
					printbuf_strappend(pb, ":");
			}

			if (CHECK_FLAG(child_flags, FRR_JSON_OPEN)) {
				/* Recurse into child */
				frr_json_obj_to_vty(vty, jval, pb, level + 1, jflags);
				lhentry = lhentry->next;
			} else if (CHECK_FLAG(child_flags, FRR_JSON_CLOSED)) {
				/* Recurse into child */
				frr_json_obj_to_vty(vty, jval, pb, level + 1, jflags);

				/* Remove child after output */
				lh_table_delete_entry(lhtable, lhentry);
				lhentry = lhtable->head;
			} else {
				/* Flush any pending output */
				vty_out(vty, "%s", pb->buf);
				printbuf_reset(pb);

				/* Use child object's buffer, flush vty output */
				str = json_object_to_json_string_ext(jval, jflags);
				vty_out(vty, "%s", str);

				/* Remove child after output */
				lh_table_delete_entry(lhtable, lhentry);
				lhentry = lhtable->head;
			}
		}

		/* Close json output if object is not "OPEN" */
		if (!CHECK_FLAG(parent_flags, FRR_JSON_OPEN) ||
		    CHECK_FLAG(parent_flags, FRR_JSON_CLOSED)) {
			if ((jflags & JSON_C_TO_STRING_PRETTY) && children_p) {
				printbuf_strappend(pb, "\n");
				frr_json_indent(pb, level, jflags);
			}
			if (jflags & JSON_C_TO_STRING_SPACED && !(jflags & JSON_C_TO_STRING_PRETTY))
				printbuf_strappend(pb, /*{*/ " }");
			else
				printbuf_strappend(pb, /*{*/ "}");
		}
	} else {
		/* Array/list type */
		for (idx = 0; idx < json_object_array_length(jobj); idx++) {
			jval = json_object_array_get_idx(jobj, idx);

			if (children_p)
				printbuf_strappend(pb, ",");
			children_p = true;

			if (jflags & JSON_C_TO_STRING_PRETTY)
				printbuf_strappend(pb, "\n");
			if (jflags & JSON_C_TO_STRING_SPACED &&
			    !(jflags & JSON_C_TO_STRING_PRETTY))
				printbuf_strappend(pb, " ");
			frr_json_indent(pb, level + 1, jflags);

			if (jval == NULL) {
				printbuf_strappend(pb, "null");
				continue;
			}

			child_flags = frr_json_get_flags(jval);
			if (CHECK_FLAG(child_flags, FRR_JSON_OPEN)) {
				/* Recurse into child */
				frr_json_obj_to_vty(vty, jval, pb, level + 1, jflags);
			} else if (CHECK_FLAG(child_flags, FRR_JSON_CLOSED)) {
				/* Recurse into child */
				frr_json_obj_to_vty(vty, jval, pb, level + 1, jflags);

				/* Remove child after output */
				json_object_array_del_idx(jobj, idx, 1);
				idx--;
			} else {
				/* Flush any pending output */
				vty_out(vty, "%s", pb->buf);
				printbuf_reset(pb);

				/* Use child object's buffer, flush vty output */
				str = json_object_to_json_string_ext(jval, jflags);
				vty_out(vty, "%s", str);

				/* Remove child after output */
				json_object_array_del_idx(jobj, idx, 1);
				idx--;
			}
		}

		/* Close jobj output if not set OPEN */
		if (!CHECK_FLAG(parent_flags, FRR_JSON_OPEN) ||
		    CHECK_FLAG(parent_flags, FRR_JSON_CLOSED)) {
			if ((jflags & JSON_C_TO_STRING_PRETTY) && children_p) {
				printbuf_strappend(pb, "\n");
				frr_json_indent(pb, level, jflags);
			}

			if (jflags & JSON_C_TO_STRING_SPACED && !(jflags & JSON_C_TO_STRING_PRETTY))
				printbuf_strappend(pb, " ]");
			else
				printbuf_strappend(pb, "]");
		}
	}

	/* Flush and free intermediate output buffer */
	if (pb_top) {
		vty_out(vty, "%s\n", pb->buf);
		printbuf_free(pb);
	}

	return 1;
}

/* Common helper for frr json output */
static void json_vty_helper(struct vty *vty, struct json_object *jobj, int flags)
{
	int frrflags;
	const char *text;

	frrflags = frr_json_get_flags(jobj);

	/* We have special handling when we're supporting incremental output. */
	if (CHECK_FLAG(frrflags, FRR_JSON_OPEN) || CHECK_FLAG(frrflags, FRR_JSON_CLOSED)) {
		frr_json_obj_to_vty(vty, jobj, NULL, 0, flags);

		/* If we're done with incremental output, free the top-level object */
		if (CHECK_FLAG(frrflags, FRR_JSON_CLOSED))
			json_object_free(jobj);
	} else {
		/* Just produce the entire output using the json lib */
		text = json_object_to_json_string_ext(jobj, flags);
		vty_out(vty, "%s\n", text);
		json_object_free(jobj);
	}
}

/*
 * FRR print/string-output function for vty output
 */
void frr_json_vty_out(struct vty *vty, struct json_object *jobj)
{
	int flags;

	flags = JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE;
	json_vty_helper(vty, jobj, flags);
}

/*
 * No-pretty/bare output variant
 */
void frr_json_vty_out_bare(struct vty *vty, struct json_object *jobj)
{
	int flags;

	flags = JSON_C_TO_STRING_NOSLASHESCAPE;
	json_vty_helper(vty, jobj, flags);
}

/*
 * Helper function to dump an outline of the json tree
 */
static void vty_json_dump_helper(struct vty *vty, struct json_object *jobj, int level)
{
	int flags;
	size_t idx;
	const char *key;
	struct json_object *jval;
	struct lh_table *lhtable;
	struct lh_entry *lhentry;
	enum json_type jtype;
	const char *typestr;

	jtype = json_object_get_type(jobj);

	/* We're only interested in object/dict and array types */
	if (jtype != json_type_object && jtype != json_type_array)
		return;

	if (jtype == json_type_array)
		typestr = "ARRAY";
	else
		typestr = "OBJ";

	flags = frr_json_get_flags(jobj);
	vty_out(vty, "%*c%s (%s%s%s%s)\n", level * 2, ' ', typestr,
		CHECK_FLAG(flags, FRR_JSON_OPEN) ? "O" : "",
		CHECK_FLAG(flags, FRR_JSON_CLOSED) ? "X" : "",
		CHECK_FLAG(flags, FRR_JSON_STARTED) ? "S" : "",
		CHECK_FLAG(flags, FRR_JSON_COLLECTION) ? "C" : "");

	level += 1;

	/* Iterate through the children of 'jobj', recurse into collections. */
	if (jtype == json_type_object) {
		lhtable = json_object_get_object(jobj);
		lhentry = lhtable->head;
		for (; lhentry; lhentry = lhentry->next) {
			jval = (struct json_object *)lh_entry_v(lhentry);
			key = (char *)lh_entry_k(lhentry);

			/* We're only interested in object/dict and array types */
			jtype = json_object_get_type(jval);
			if (jtype != json_type_object && jtype != json_type_array)
				continue;

			/* Print child's key */
			vty_out(vty, "%*c%s: ", level * 2, ' ', key);

			/* Print child and its children */
			vty_json_dump_helper(vty, jval, level);
		}
	} else {
		/* Array/list type */
		for (idx = 0; idx < json_object_array_length(jobj); idx++) {
			/* We're only interested in object/dict and array types */
			jval = json_object_array_get_idx(jobj, idx);
			if (jval == NULL)
				continue;

			jtype = json_object_get_type(jval);
			if (jtype != json_type_object && jtype != json_type_array)
				continue;

			/* Print child's key */
			vty_out(vty, "%*c[%zu] ", level * 2, ' ', idx);

			/* Print child and its children */
			vty_json_dump_helper(vty, jval, level);
		}
	}
}

/*
 * Dump an outline of the json hierarchy to vty: print out the keys and types
 * of container objects at each level.
 */
void frr_vty_json_dump(struct vty *vty, struct json_object *jobj)
{
	/* Recurse down the tree... */
	vty_json_dump_helper(vty, jobj, 0);
}

/*
 * Flag that an object (a collection) is not yet complete; don't emit end-of-collection
 * text yet, as more children may be added.
 */
void frr_json_set_open(struct json_object *jobj)
{
	int frrflags;

	frrflags = frr_json_get_flags(jobj);
	SET_FLAG(frrflags, FRR_JSON_OPEN);

	frr_json_set_data(jobj, frrflags);
}

/*
 * Indicate that an object is complete; during the next output function call,
 * emit end-of-collection text, and free the object
 */
void frr_json_set_complete(struct json_object *jobj)
{
	int frrflags;

	frrflags = frr_json_get_flags(jobj);

	if (CHECK_FLAG(frrflags, FRR_JSON_OPEN))
		SET_FLAG(frrflags, FRR_JSON_CLOSED);

	UNSET_FLAG(frrflags, FRR_JSON_OPEN);

	frr_json_set_data(jobj, frrflags);
}

#else /* Older libjson-c version, no incremental support */

#define FRR_OPEN_STR  "frr"
#define FRR_CLOSE_STR " "

static void json_vty_helper(struct vty *vty, struct json_object *jobj, int flags)
{
	struct printbuf *pb;
	const char *text;

	pb = printbuf_new();

	json_object_userdata_to_json_string(jobj, pb, 0, 0);

	/* Ignore 'open' object; emit complete output otherwise */
	if (strcmp(pb->buf, FRR_OPEN_STR) != 0) {
		/* Just produce the entire output using the json lib */
		text = json_object_to_json_string_ext(jobj, flags);
		vty_out(vty, "%s\n", text);
		json_object_free(jobj);
	}

	printbuf_free(pb);
}

void frr_json_vty_out(struct vty *vty, struct json_object *jobj)
{
	json_vty_helper(vty, jobj,
			JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
}

void frr_json_vty_out_bare(struct vty *vty, struct json_object *jobj)
{
	json_vty_helper(vty, jobj, JSON_C_TO_STRING_NOSLASHESCAPE);
}

void frr_vty_json_dump(struct vty *vty, struct json_object *jobj)
{
	vty_out(vty, "{}\n");
}

/* Delete helper function for json object userdata */
static void frr_jobj_del_func(struct json_object *jobj, void *data)
{
	if (data)
		free(data);
}

/*
 * Flag that an object (a collection) is not yet complete; don't emit end-of-collection
 * text yet, as more children may be added.
 */
void frr_json_set_open(struct json_object *jobj)
{
	char *str = malloc(4);

	strlcpy(str, FRR_OPEN_STR, 4);
	json_object_set_serializer(jobj, NULL, str, frr_jobj_del_func);
}

/*
 * Indicate that an object is complete; during the next output function call,
 * emit end-of-collection text, and free the object and its children.
 */
void frr_json_set_complete(struct json_object *jobj)
{
	char *str = malloc(4);

	strlcpy(str, FRR_CLOSE_STR, 4);
	json_object_set_serializer(jobj, NULL, str, frr_jobj_del_func);
}

#endif /* libjson-c version dependencies */
