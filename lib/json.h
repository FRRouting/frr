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

#ifndef _QUAGGA_JSON_H
#define _QUAGGA_JSON_H

#if defined(HAVE_JSON_C_JSON_H)
#include <json-c/json.h>
#else
#include <json/json.h>
#endif

extern int use_json(const int argc, const char *argv[]);
extern void json_object_string_add(struct json_object* obj, const char *key,
                                   const char *s);
extern void json_object_int_add(struct json_object* obj, const char *key,
                                int32_t i);
extern void json_object_boolean_false_add(struct json_object* obj,
                                          const char *key);
extern void json_object_boolean_true_add(struct json_object* obj,
                                         const char *key);
extern struct json_object* json_object_lock(struct json_object *obj);
extern void json_object_free(struct json_object *obj);

#endif /* _QUAGGA_JSON_H */
