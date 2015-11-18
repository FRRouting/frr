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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <string.h>
#include "lib/json.h"

/*
 * This function assumes that the json keyword
 * is the *last* keyword on the line no matter
 * what.
 */
int
use_json (const int argc, const char *argv[])
{
  if (argc == 0)
    return 0;

  if (argv[argc-1] && strcmp(argv[argc-1], "json") == 0)
    return 1;

  return 0;
}

void
json_object_string_add(struct json_object* obj, const char *key,
                       const char *s)
{
  json_object_object_add(obj, key, json_object_new_string(s));
}

void
json_object_int_add(struct json_object* obj, const char *key, int32_t i)
{
  json_object_object_add(obj, key, json_object_new_int(i));
}

void
json_object_boolean_false_add(struct json_object* obj, const char *key)
{
  json_object_object_add(obj, key, json_object_new_boolean(0));
}

void
json_object_boolean_true_add(struct json_object* obj, const char *key)
{
  json_object_object_add(obj, key, json_object_new_boolean(1));
}

struct json_object*
json_object_lock(struct json_object *obj)
{
  return json_object_get(obj);
}

void
json_object_free(struct json_object *obj)
{
  json_object_put(obj);
}
