/* json-c wrapper
 * Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "lib/json.h"

/*
 * This function assumes that the json keyword
 * is the *last* keyword on the line no matter
 * what.
 */
int use_json(const int argc, struct cmd_token *argv[])
{
	if (argc == 0)
		return 0;

	if (argv[argc - 1]->arg && strmatch(argv[argc - 1]->text, "json"))
		return 1;

	return 0;
}

void json_object_string_add(struct json_object *obj, const char *key,
			    const char *s)
{
	json_object_object_add(obj, key, json_object_new_string(s));
}

void json_object_int_add(struct json_object *obj, const char *key, int64_t i)
{
#if defined(HAVE_JSON_C_JSON_H)
	json_object_object_add(obj, key, json_object_new_int64(i));
#else
	json_object_object_add(obj, key, json_object_new_int((int)i));
#endif
}

void json_object_boolean_false_add(struct json_object *obj, const char *key)
{
	json_object_object_add(obj, key, json_object_new_boolean(0));
}

void json_object_boolean_true_add(struct json_object *obj, const char *key)
{
	json_object_object_add(obj, key, json_object_new_boolean(1));
}

struct json_object *json_object_lock(struct json_object *obj)
{
	return json_object_get(obj);
}

void json_object_free(struct json_object *obj)
{
	json_object_put(obj);
}

#if !defined(HAVE_JSON_C_JSON_H)
int json_object_object_get_ex(struct json_object *obj, const char *key,
			      struct json_object **value)
{
	*value = json_object_object_get(obj, key);

	if (*value)
		return 1;

	return 0;
}
#endif
