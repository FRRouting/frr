// SPDX-License-Identifier: GPL-2.0-or-later
/* json-c wrapper
 * Copyright (C) 2015 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "command.h"
#include "lib/json.h"

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
