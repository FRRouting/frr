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

#ifndef _QUAGGA_JSON_H
#define _QUAGGA_JSON_H

#ifdef __cplusplus
extern "C" {
#endif

#include "command.h"
#include "printfrr.h"
#include <json-c/json.h>

/*
 * FRR style JSON iteration.
 * Usage: JSON_FOREACH(...) { ... }
 */
#define JSON_FOREACH(jo, joi, join)                                            \
	/* struct json_object *jo; */                                          \
	/* struct json_object_iterator joi; */                                 \
	/* struct json_object_iterator join; */                                \
	for ((joi) = json_object_iter_begin((jo)),                             \
	    (join) = json_object_iter_end((jo));                               \
	     json_object_iter_equal(&(joi), &(join)) == 0;                     \
	     json_object_iter_next(&(joi)))

extern bool use_json(const int argc, struct cmd_token *argv[]);
extern void json_object_string_add(struct json_object *obj, const char *key,
				   const char *s);
extern void json_object_int_add(struct json_object *obj, const char *key,
				int64_t i);
void json_object_boolean_add(struct json_object *obj, const char *key,
			     bool val);

extern void json_object_double_add(struct json_object *obj, const char *key,
				   double i);
extern void json_object_boolean_false_add(struct json_object *obj,
					  const char *key);
extern void json_object_boolean_true_add(struct json_object *obj,
					 const char *key);
extern struct json_object *json_object_lock(struct json_object *obj);
extern void json_object_free(struct json_object *obj);
extern void json_array_string_add(json_object *json, const char *str);

/* printfrr => json helpers */

PRINTFRR(3, 0)
extern void json_object_string_addv(struct json_object *obj, const char *key,
				    const char *fmt, va_list args);
PRINTFRR(3, 4)
static inline void json_object_string_addf(struct json_object *obj,
					   const char *key, const char *fmt,
					   ...)
{
	va_list args;

	va_start(args, fmt);
	json_object_string_addv(obj, key, fmt, args);
	va_end(args);
}

PRINTFRR(2, 0)
extern void json_array_string_addv(json_object *json, const char *fmt,
				   va_list args);
PRINTFRR(2, 3)
static inline void json_array_string_addf(struct json_object *obj,
					  const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	json_array_string_addv(obj, fmt, args);
	va_end(args);
}

PRINTFRR(1, 0)
extern struct json_object *json_object_new_stringv(const char *fmt,
						   va_list args);
PRINTFRR(1, 2)
static inline struct json_object *json_object_new_stringf(const char *fmt, ...)
{
	struct json_object *ret;
	va_list args;

	va_start(args, fmt);
	ret = json_object_new_stringv(fmt, args);
	va_end(args);

	return ret;
}

#define JSON_STR "JavaScript Object Notation\n"

/* NOTE: json-c lib has following commit 316da85 which
 * handles escape of forward slash.
 * This allows prefix  "20.0.14.0\/24":{
 * to  "20.0.14.0/24":{ some platforms do not have
 * latest copy of json-c where defining below macro.
 */

#ifndef JSON_C_TO_STRING_NOSLASHESCAPE

/**
  * Don't escape forward slashes.
  */
#define JSON_C_TO_STRING_NOSLASHESCAPE (1<<4)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _QUAGGA_JSON_H */
