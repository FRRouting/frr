/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_YANG_TRANSLATOR_H_
#define _FRR_YANG_TRANSLATOR_H_

#ifdef __cplusplus
extern "C" {
#endif

#define YANG_TRANSLATE_TO_NATIVE 0
#define YANG_TRANSLATE_FROM_NATIVE 1
#define YANG_TRANSLATE_MAX 2

struct yang_tmodule {
	const struct lys_module *module;
	const struct lys_module *deviations;
	uint32_t nodes_before_deviations;
	uint32_t nodes_after_deviations;
	double coverage;
};

struct yang_translator {
	RB_ENTRY(yang_translator) entry;
	char family[32];
	struct ly_ctx *ly_ctx;
	struct list *modules;
	struct hash *mappings[YANG_TRANSLATE_MAX];
};
RB_HEAD(yang_translators, yang_translator);
RB_PROTOTYPE(yang_translators, yang_translator, entry, yang_translator_compare);

enum yang_translate_result {
	YANG_TRANSLATE_SUCCESS,
	YANG_TRANSLATE_NOTFOUND,
	YANG_TRANSLATE_FAILURE,
};

/* Tree of all loaded YANG module translators. */
extern struct yang_translators yang_translators;

/*
 * Load a YANG module translator from a JSON file.
 *
 * path
 *    Absolute path to the module translator file.
 *
 * Returns:
 *    Pointer to newly created YANG module translator, or NULL in the case of an
 *    error.
 */
extern struct yang_translator *yang_translator_load(const char *path);

/*
 * Unload a YANG module translator.
 *
 * translator
 *    Pointer to the YANG module translator.
 */
extern void yang_translator_unload(struct yang_translator *translator);

/*
 * Find a YANG module translator by its family name.
 *
 * family
 *    Family of the YANG module translator (e.g. ietf, openconfig).
 *
 * Returns:
 *    Pointer to the YANG module translator if found, NULL otherwise.
 */
extern struct yang_translator *yang_translator_find(const char *family);

/*
 * Translate an XPath expression.
 *
 * translator
 *    Pointer to YANG module translator.
 *
 * dir
 *    Direction of the translation (either YANG_TRANSLATE_TO_NATIVE or
 *    YANG_TRANSLATE_FROM_NATIVE).
 *
 * xpath
 *    Pointer to previously allocated buffer containing the xpath expression to
 *    be translated.
 *
 * xpath_len
 *    Size of the xpath buffer.
 *
 * Returns:
 *    - YANG_TRANSLATE_SUCCESS on success.
 *    - YANG_TRANSLATE_NOTFOUND when there's no available mapping to perform
 *      the translation.
 *    - YANG_TRANSLATE_FAILURE when an error occurred during the translation.
 */
extern enum yang_translate_result
yang_translate_xpath(const struct yang_translator *translator, int dir,
		     char *xpath, size_t xpath_len);

/*
 * Translate an entire libyang data node.
 *
 * translator
 *    Pointer to YANG module translator.
 *
 * dir
 *    Direction of the translation (either YANG_TRANSLATE_TO_NATIVE or
 *    YANG_TRANSLATE_FROM_NATIVE).
 *
 * dnode
 *    libyang schema node we want to translate.
 *
 * Returns:
 *    - YANG_TRANSLATE_SUCCESS on success.
 *    - YANG_TRANSLATE_FAILURE when an error occurred during the translation.
 */
extern int yang_translate_dnode(const struct yang_translator *translator,
				int dir, struct lyd_node **dnode);

/*
 * Initialize the YANG module translator subsystem. Should be called only once
 * during the daemon initialization process.
 */
extern void yang_translator_init(void);

/*
 * Finish the YANG module translator subsystem gracefully. Should be called only
 * when the daemon is exiting.
 */
extern void yang_translator_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_YANG_TRANSLATOR_H_ */
