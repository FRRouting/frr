// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <inttypes.h>

#include "ferr.h"
#include "vty.h"
#include "jhash.h"
#include "memory.h"
#include "hash.h"
#include "command.h"
#include "json.h"
#include "linklist.h"
#include "frr_pthread.h"

DEFINE_MTYPE_STATIC(LIB, ERRINFO, "error information");

/*
 * Thread-specific key for temporary storage of allocated ferr.
 */
static pthread_key_t errkey;

static void ferr_free(void *arg)
{
	XFREE(MTYPE_ERRINFO, arg);
}

static void err_key_init(void) __attribute__((_CONSTRUCTOR(500)));
static void err_key_init(void)
{
	pthread_key_create(&errkey, ferr_free);
}

static void err_key_fini(void) __attribute__((_DESTRUCTOR(500)));
static void err_key_fini(void)
{
	pthread_key_delete(errkey);
}

/*
 * Global shared hash table holding reference text for all defined errors.
 */
static pthread_mutex_t refs_mtx = PTHREAD_MUTEX_INITIALIZER;
struct hash *refs;

static bool ferr_hash_cmp(const void *a, const void *b)
{
	const struct log_ref *f_a = a;
	const struct log_ref *f_b = b;

	return f_a->code == f_b->code;
}

static inline unsigned int ferr_hash_key(const void *a)
{
	const struct log_ref *f = a;

	return f->code;
}

void log_ref_add(struct log_ref *ref)
{
	uint32_t i = 0;

	frr_with_mutex (&refs_mtx) {
		while (ref[i].code != END_FERR) {
			(void)hash_get(refs, &ref[i], hash_alloc_intern);
			i++;
		}
	}
}

struct log_ref *log_ref_get(uint32_t code)
{
	struct log_ref holder;
	struct log_ref *ref;

	holder.code = code;
	frr_with_mutex (&refs_mtx) {
		ref = hash_lookup(refs, &holder);
	}

	return ref;
}

void log_ref_display(struct vty *vty, uint32_t code, bool json)
{
	struct log_ref *ref;
	struct json_object *top = NULL, *obj = NULL;
	struct list *errlist;
	struct listnode *ln;

	if (json)
		top = json_object_new_object();

	frr_with_mutex (&refs_mtx) {
		errlist = code ? list_new() : hash_to_list(refs);
	}

	if (code) {
		ref = log_ref_get(code);
		if (!ref) {
			if (top)
				json_object_free(top);
			list_delete(&errlist);
			return;
		}
		listnode_add(errlist, ref);
	}

	for (ALL_LIST_ELEMENTS_RO(errlist, ln, ref)) {
		if (json) {
			char key[11];

			snprintf(key, sizeof(key), "%u", ref->code);
			obj = json_object_new_object();
			json_object_string_add(obj, "title", ref->title);
			json_object_string_add(obj, "description",
					       ref->description);
			json_object_string_add(obj, "suggestion",
					       ref->suggestion);
			json_object_object_add(top, key, obj);
		} else {
			char pbuf[256];
			char ubuf[256];

			snprintf(pbuf, sizeof(pbuf), "\nError %u - %s",
				 ref->code, ref->title);
			memset(ubuf, '=', strlen(pbuf));
			ubuf[strlen(pbuf)] = '\0';

			vty_out(vty, "%s\n%s\n", pbuf, ubuf);
			vty_out(vty, "Description:\n%s\n\n", ref->description);
			vty_out(vty, "Recommendation:\n%s\n", ref->suggestion);
		}
	}

	vty_json(vty, top);
	list_delete(&errlist);
}

DEFUN_NOSH(show_error_code,
	   show_error_code_cmd,
	   "show error <(1-4294967295)|all> [json]",
	   SHOW_STR
	   "Information on errors\n"
	   "Error code to get info about\n"
	   "Information on all errors\n"
	   JSON_STR)
{
	bool json = strmatch(argv[argc-1]->text, "json");
	uint32_t arg = 0;

	if (!strmatch(argv[2]->text, "all"))
		arg = strtoul(argv[2]->arg, NULL, 10);

	log_ref_display(vty, arg, json);
	return CMD_SUCCESS;
}

void log_ref_init(void)
{
	frr_with_mutex (&refs_mtx) {
		refs = hash_create(ferr_hash_key, ferr_hash_cmp,
				   "Error Reference Texts");
	}
}

void log_ref_fini(void)
{
	frr_with_mutex (&refs_mtx) {
		hash_clean_and_free(&refs, NULL);
	}
}

void log_ref_vty_init(void)
{
	install_element(VIEW_NODE, &show_error_code_cmd);
}


const struct ferr *ferr_get_last(ferr_r errval)
{
	struct ferr *last_error = pthread_getspecific(errkey);
	if (!last_error || last_error->kind == 0)
		return NULL;
	return last_error;
}

ferr_r ferr_clear(void)
{
	struct ferr *last_error = pthread_getspecific(errkey);
	if (last_error)
		last_error->kind = 0;
	return ferr_ok();
}

PRINTFRR(7, 0)
static ferr_r ferr_set_va(const char *file, int line, const char *func,
			  enum ferr_kind kind, const char *pathname,
			  int errno_val, const char *text, va_list va)
{
	struct ferr *error = pthread_getspecific(errkey);

	if (!error) {
		error = XCALLOC(MTYPE_ERRINFO, sizeof(*error));

		pthread_setspecific(errkey, error);
	}

	error->file = file;
	error->line = line;
	error->func = func;
	error->kind = kind;

	error->unique_id = jhash(text, strlen(text),
				 jhash(file, strlen(file), 0xd4ed0298));

	error->errno_val = errno_val;
	if (pathname)
		snprintf(error->pathname, sizeof(error->pathname), "%s",
			 pathname);
	else
		error->pathname[0] = '\0';

	vsnprintf(error->message, sizeof(error->message), text, va);
	return -1;
}

ferr_r ferr_set_internal(const char *file, int line, const char *func,
			 enum ferr_kind kind, const char *text, ...)
{
	ferr_r rv;
	va_list va;
	va_start(va, text);
	rv = ferr_set_va(file, line, func, kind, NULL, 0, text, va);
	va_end(va);
	return rv;
}

ferr_r ferr_set_internal_ext(const char *file, int line, const char *func,
			     enum ferr_kind kind, const char *pathname,
			     int errno_val, const char *text, ...)
{
	ferr_r rv;
	va_list va;
	va_start(va, text);
	rv = ferr_set_va(file, line, func, kind, pathname, errno_val, text, va);
	va_end(va);
	return rv;
}

#define REPLACE "$ERR"
void vty_print_error(struct vty *vty, ferr_r err, const char *msg, ...)
{
	char tmpmsg[512], *replacepos;
	const struct ferr *last_error = ferr_get_last(err);

	va_list va;
	va_start(va, msg);
	vsnprintf(tmpmsg, sizeof(tmpmsg), msg, va);
	va_end(va);

	replacepos = strstr(tmpmsg, REPLACE);
	if (!replacepos)
		vty_out(vty, "%s\n", tmpmsg);
	else {
		replacepos[0] = '\0';
		replacepos += sizeof(REPLACE) - 1;
		vty_out(vty, "%s%s%s\n", tmpmsg,
			last_error ? last_error->message : "(no error?)",
			replacepos);
	}
}
