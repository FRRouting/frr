/*
 * Zebra Script Wrapper
 * Copyright (C) 2018  6WIND
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
#include <zebra.h>
#include "json.h"
#include "version.h"
#include "hook.h"
#include "libfrr.h"

#include "zebra/debug.h"
#include "zebra/zebra_pbr.h"

/* this struct temporarily stores the list of headers
 * - name is used to store the name of the header field
 * - attribute can be used to store values that have no column
 * assigned ( extra param)
 * ex:
 *  columnA   columnB       columnC    columnD
 *    <val1>   <val2>        <val3>     <val4>       <val5> <val6>..
 *    <val7>   <val8>        <val9>     <val10>    <val11> <val12>..
 * columnA .. columnD are stored in name field
 * attribute us used to store <val5>..<val6> or <val11>..<val12>
 */
struct item_list {
	char *name;
	char *attribute;
};

#define DATA_LEN 4096
#define ITEM_MAXIMUM 15
#define DATA_LINE_MAX 200

/* debug information */
#define SCRIPT_DEBUG	(1<<1)
#define SCRIPT_ITEM_LIST	(1<<2)
#define SCRIPT_ELEMENT_LIST	(1<<3)

static int zebra_wrap_debug;

static int zebra_wrap_script_column(const char *script,
				     int begin_at_line,
				     struct json_object *json_obj_list,
				     char *switch_to_mode_row_at);
static int zebra_wrap_script_rows(const char *script,
			    int begin_at_line,
			    struct json_object *json_obj_list);
static int zebra_wrap_script_get_stat(struct json_object *json_input,
				      const char *pattern,
				      const char *match,
				      uint64_t *pkts, uint64_t *bytes);
static int zebra_wrap_script_init(struct thread_master *t);

static int zebra_wrap_script_module_init(void)
{
	hook_register(zebra_pbr_wrap_script_rows,
		      zebra_wrap_script_rows);
	hook_register(zebra_pbr_wrap_script_column,
		      zebra_wrap_script_column);
	hook_register(zebra_pbr_wrap_script_get_stat,
		      zebra_wrap_script_get_stat);
	hook_register(frr_late_init, zebra_wrap_script_init);
	return 0;
}

FRR_MODULE_SETUP(
		 .name = "zebra_wrap",
		 .version = FRR_VERSION,
		 .description = "zebra wrap script module",
		 .init = zebra_wrap_script_module_init
		 );

static bool isseparator(char car, char separator_list[])
{
	int i = 0;

	do {
		if (separator_list[i] == '\0')
			return false;
		if (separator_list[i] == car)
			return true;
		i++;
	} while (1);
	/* should never occur */
	return false;
}

/* this function gets a word from the input string
 * based on an input separator list of chars,
 * and returns that word.
 * TODO : strsep should be used in this routine
 */
static int search_current_word(char *current_str, int init,
			       char current_word[],
			       int current_word_len,
			       char separator[])
{
	bool word_began = false;
	char *ptr_word;
	int k, l = 0, m = 0;

	for (k = init; k < (int)strlen(current_str); k++) {
		m ++;
		/* a word is made up of a char
		 * or a digit
		 * or a character between '!' and '/'
		 */
		if (word_began == false &&
		    (isalpha(current_str[k])
		     || isdigit(current_str[k])
		     || (current_str[k] > 0x21
			 && current_str[k] < 0x2f))) {
			ptr_word = &(current_str[k]);
			word_began = true;
			l = 0;
		}
		if (word_began == false)
			continue;
		if (!isseparator(current_str[k], separator)) {
			l += 1;
			continue;
		}
		memcpy(current_word, ptr_word, (size_t)l);
		current_word[l] = '\0';
		return m;
	}
	if (word_began) {
		memcpy(current_word, ptr_word, (size_t)l);
		current_word[l] = '\0';
		return m;
	}
	return -1;
}

/*
 * 1.1.1.2,2.2.2.2 packets 0 bytes 0
 * 172.17.0.0/24,172.17.0.31 packets 0 bytes 0
 */
static int handle_field_line_special(struct json_object *json_obj,
				    char *current_str, char separator[])
{
	int k, l = 0;
	char current_field[DATA_LINE_MAX];
	char current_attribute[DATA_LINE_MAX];
	const char *data = "data";

	/* get headers from current_str */
	for (k = 0; k < (int)strlen(current_str);) {
		/* first has no field. use data */
		l = search_current_word(current_str, k,
					current_attribute,
					sizeof(current_attribute),
					separator);
		if (l < 0)
			break;
		k += l;
		json_object_string_add(json_obj,
				       data,
				       current_attribute);
		if (zebra_wrap_debug
		    & SCRIPT_ELEMENT_LIST)
			zlog_err("ITEM Obtained for %s is %s",
				 data, current_attribute);

		/* get packets */
		l = search_current_word(current_str, k,
					current_attribute,
					sizeof(current_attribute),
					separator);
		if (l < 0)
			break;
		k += l;
		/* get value of packets */
		l = search_current_word(current_str, k,
					current_field,
					sizeof(current_field),
					separator);
		if (l < 0)
			break;
		k += l;
		if (strcmp(current_attribute, "packets") == 0)
			json_object_string_add(json_obj,
					       "pkts",
					       current_field);
		else
			json_object_string_add(json_obj,
					       current_attribute,
					       current_field);
		if (zebra_wrap_debug
		    & SCRIPT_ELEMENT_LIST)
			zlog_err("ITEM Obtained "
				 "for %s is %s",
				 current_attribute,
				 current_field);
		/* get bytes */
		l = search_current_word(current_str, k,
					current_attribute,
					sizeof(current_attribute),
					separator);
		if (l < 0)
			break;
		k += l;
		/* get value of bytes */
		l = search_current_word(current_str, k,
					current_field,
					sizeof(current_field),
					separator);
		if (l < 0)
			break;
		k += l;
		if (zebra_wrap_debug
		    & SCRIPT_ELEMENT_LIST)
			zlog_err("ITEM Obtained for %s is %s",
				 current_attribute, current_field);
		json_object_string_add(json_obj,
				       current_attribute,
				       current_field);
	}
	return 0;
}

static int handle_field_line_column(struct json_object *json_obj,
				    char *current_str, char separator[])
{
	int k, l = 0;
	char current_field[DATA_LINE_MAX];
	int nb_items = 0;

	/* get headers from current_str */
	for (k = 0; k < (int)strlen(current_str);) {
		l = search_current_word(current_str, k,
					current_field,
					sizeof(current_field),
					separator);
		if (l < 0)
			break;
		k += l;
		/* first word obtained
		 * now grab rest of the line
		 */
		json_object_string_add(json_obj,
				       current_field,
				       &current_str[k]);
		if (zebra_wrap_debug
		    & SCRIPT_ELEMENT_LIST)
			zlog_err("(%d)ITEM Obtained for %s is %s",
				 nb_items, current_field,
				 &current_str[k]);
		return 0;
	}
	return 0;
}

static int handle_field_line_row(struct json_object *json_obj,
				 char *current_str,
				 struct item_list item[],
				 char separator[])
{
	int k, l = 0;
	char current_word[DATA_LINE_MAX];
	int nb_items = 0;
	bool keep_item = false;

	/* get headers from current_str */
	for (k = 0; k < (int)strlen(current_str);) {
		l = search_current_word(current_str, k,
					current_word,
					sizeof(current_word),
					separator);
		if (l < 0)
			break;
		k += l;
		/* no json obj. fields are filled in */
		if (json_obj == NULL) {
			if (zebra_wrap_debug
			    & SCRIPT_ITEM_LIST)
				zlog_err("SCRIPT: (%d)ITEM %s",
					 nb_items, current_word);
			item[nb_items].name =
				XSTRDUP(MTYPE_TMP, current_word);
		} else {
			/* if a field has no column, create "misc" column */
			if (!item[nb_items].name) {
				item[nb_items].name =
					XSTRDUP(MTYPE_TMP, "misc");
				keep_item = true;
				item[nb_items].attribute =
					XSTRDUP(MTYPE_TMP,
						current_word);
			} else if (item[nb_items].attribute) {
				/* store last elements in attribute */
				char temp_word[DATA_LINE_MAX];

				snprintf(temp_word,
					 DATA_LINE_MAX,
					 "%s %s",
					 item[nb_items].attribute,
					 current_word);
				XFREE(MTYPE_TMP,
				      item[nb_items].attribute);
				item[nb_items].attribute =
					XSTRDUP(MTYPE_TMP,
						temp_word);
			}
			if (!keep_item) {
				json_object_string_add(json_obj,
						       item[nb_items].name,
						       current_word);
				if (zebra_wrap_debug
				    & SCRIPT_ELEMENT_LIST)
					zlog_err("(%d)ITEM Obtained "
						 "for %s is %s",
						 nb_items,
						 item[nb_items].name,
						 current_word);
			}
		}
		if (!keep_item)
			nb_items++;
		if (nb_items >= ITEM_MAXIMUM) {
			int m;

			for (m = 0; m < ITEM_MAXIMUM; m++)
				XFREE(MTYPE_TMP, item[m].name);
			if (json_obj)
				json_object_free(json_obj);
			return -1;
		}
	}
	/* store last attribute to json
	 */
	if (keep_item) {
		json_object_string_add(json_obj,
				       item[nb_items].name,
				       item[nb_items].attribute);
		if (zebra_wrap_debug & SCRIPT_ITEM_LIST)
			zlog_err("(%d)ITEM Obtained for %s is %s",
				 nb_items, item[nb_items].name,
				 item[nb_items].attribute);
		XFREE(MTYPE_TMP, item[nb_items].attribute);
		item[nb_items].attribute = NULL;
		XFREE(MTYPE_TMP, item[nb_items].name);
		item[nb_items].name = NULL;
	}
	return 0;
}

/*
 * Name: match0x39ea2d0
 * Type: hash:net,net
 * Revision: 2
 * Header: family inet hashsize 64 maxelem 65536 counters
 * Size in memory: 824
 * References: 1
 * Number of entries: 2
 * Members:
 * 1.1.1.2,2.2.2.2 packets 0 bytes 0
 * 172.17.0.0/24,172.17.0.31 packets 0 bytes 0
 *
 * from the output of a similar script, a json array is given back
 * in following shape:
 * {"0"}:{"Name":"match0x39..","Type":"hash:net,net",
 * "Number of Entries":"2"},{"1"}:{"data":"1.1.1.2,2.2.2.2",
 * "pkts":"0","bytes":"0"}
 */
static int zebra_wrap_script_column(const char *script,
				    int begin_at_line,
				    struct json_object *json_obj_list,
				    char *switch_to_mode_row_at)
{
	FILE *fp;
	char data[DATA_LEN];
	char *current_str = NULL;
	int line_nb = 0;
	int nb_entries = 0;
	bool column_mode = true;

	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
		zlog_debug("SCRIPT : %s", script);
	fp = popen(script, "r");
	if (!fp) {
		zlog_err("SCRIPT: error calling %s", script);
		return -1;
	}
	do {
		json_object *json_obj = NULL;
		char separator[5];

		memset(separator, 0, sizeof(separator));
		separator[0] = ':';
		separator[1] = ' ';
		memset(data, 0, DATA_LEN);
		current_str = fgets(data, DATA_LEN, fp);
		if (current_str) {
			char line[10];

			/* data contains the line */
			current_str = data;
			if (zebra_wrap_debug & SCRIPT_DEBUG)
				zlog_debug("SCRIPT : [%d/%d] %s",
					   line_nb,
					   (int)strlen(current_str),
					   current_str);
			if ((strlen(current_str) <= 1) ||
			    line_nb < begin_at_line) {
				line_nb++;
				continue;
			}
			/* column mode, same json obj is reused */
			if (!json_obj)
				json_obj = json_object_new_object();
			if (column_mode == true) {
				/* check if switch_to_mode_row_at
				 * is eligible
				 */
				if (switch_to_mode_row_at &&
				    strstr(current_str,
					   switch_to_mode_row_at)) {
					column_mode = false;
				} else {
					handle_field_line_column(json_obj,
								 current_str,
								 separator);
					snprintf(line, sizeof(line), "%d",
						 nb_entries);
					json_object_object_add(json_obj_list,
							       line,
							       json_obj);
					json_obj = NULL;
					nb_entries++;
				}
				continue;
			}
			if (column_mode == false) {
				memset(separator, 0, sizeof(separator));
				separator[0] = ' ';
				separator[1] = '\n';
				if (handle_field_line_special(json_obj,
							      current_str,
							      separator) < 0) {
					json_object_free(json_obj);
					return -1;
				}
				snprintf(line, sizeof(line), "%d", nb_entries);
				json_object_object_add(json_obj_list,
						       line, json_obj);
				json_obj = NULL;
				nb_entries++;
			}
		}
	} while (current_str != NULL);
	if (pclose(fp))
		zlog_err("SCRIPT: error closing stream with %s", script);
	return 0;
}

/* script : command line to execute in a shell script
 * return_data : set to true if want to get back some information
 * begin_at_line : the line number where to begin parsing headers and other
 * - ex: following dump example begins at line 2, where header is located
 *    # iptables -t mangle -L PREROUTING -v
 *    Chain PREROUTING (policy ACCEPT 150k packets, 7426 bytes)     (## line 0)
 *     pkts bytes target    prot opt in    out source   destination (## line 1)
 *     0     0     DROP      all --  any   any anywhere  anywhere
 *          match-set match0x55f44       (## line 2)
 * json_obj_list : the json structure mapped to the output, ranked with line nb
 * - ex: above dump gives following
 * { "2":{"pkts":"0","bytes":"0","target":"MARK","prot":"all", \
 *           "opt":"--","in":"any",..}}
 */
static int zebra_wrap_script_rows(const char *script,
			   int begin_at_line,
			   struct json_object *json_obj_list)
{
	FILE *fp;
	char data[DATA_LEN];
	char *current_str = NULL;
	int nb_entries = 0;
	int line_nb = 0, i;
	struct item_list item[ITEM_MAXIMUM];

	/* initialise item list
	 */
	for (i = 0; i < ITEM_MAXIMUM; i++)
		memset(&item[i], 0, sizeof(struct item_list));
	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
		zlog_debug("SCRIPT : %s", script);
	fp = popen(script, "r");
	if (!fp) {
		zlog_err("SCRIPT: error calling %s", script);
		return -1;
	}
	do {
		json_object *json_obj = NULL;
		char separator[5];

		memset(separator, 0, sizeof(separator));
		separator[0] = ' ';
		memset(data, 0, DATA_LEN);
		current_str = fgets(data, DATA_LEN, fp);
		if (current_str) {
			/* data contains the line */
			current_str = data;
			if (zebra_wrap_debug & SCRIPT_DEBUG)
				zlog_debug("SCRIPT : [%d/%d] %s",
					   line_nb,
					   (int)strlen(current_str),
					   current_str);
			if ((strlen(current_str) <= 1) ||
			    line_nb < begin_at_line) {
				line_nb++;
				continue;
			}
			if (line_nb > begin_at_line)
				json_obj = json_object_new_object();
			else
				json_obj = NULL;
			if (handle_field_line_row(json_obj, current_str,
						  item, separator) < 0)
				return -1;
			if (json_obj) {
				char line[10];

				snprintf(line, sizeof(line), "%d", nb_entries);
				json_object_object_add(json_obj_list,
						       line, json_obj);
				nb_entries++;
			}
			line_nb++;
		}
	} while (current_str != NULL);
	/* free item list */
	for (i = 0; i < ITEM_MAXIMUM; i++) {
		if (item[i].name) {
			XFREE(MTYPE_TMP, item[i].name);
			item[i].name = NULL;
		}
	}
	if (pclose(fp))
		zlog_err("SCRIPT: error closing stream with %s", script);
	return 0;
}

/* convert string <NUM>[K,M,G] into int64 value
 * last letter of the word is a multiplier
 * remove it and apply atoll
 */
static void zebra_wrap_script_convert_stat(const char *from, uint64_t *to,
					   uint64_t multiplier)
{
	char buff_tmp[64];
	char *ptr_check = NULL;

	if (!from) {
		*to = 0;
		return;
	}
	strncpy(buff_tmp, from, sizeof(buff_tmp) - 1);
	buff_tmp[63] = '\0';
	*to = strtoull(buff_tmp, &ptr_check, 10);
	if (ptr_check) {
		if (*ptr_check == 'K')
			*to *= 1000;
		else if (*ptr_check == 'M')
			*to *= 1000000;
		else if (*ptr_check == 'G')
			*to *= 1000000000;
		else if (*ptr_check != '\0')
			*to = 0;
	}
}

static int zebra_wrap_script_get_stat(struct json_object *json_input,
				      const char *pattern,
				      const char *match,
				      uint64_t *pkts, uint64_t *bytes)
{
	struct json_object *json;
	struct json_object *json_misc = NULL;
	int i = 0;
	char buff[10];
	struct json_object *json_temp;
	int ret = 1;

	if (zebra_wrap_debug & SCRIPT_DEBUG)
		zlog_debug("SCRIPT : get_stat pattern %s match %s",
			   pattern, match);
	if (!json_input)
		return -1;

	do {
		json = NULL;
		snprintf(buff, sizeof(buff), "%d", i);
		json_object_object_get_ex(json_input, buff, &json);
		if (!json)
			return -1;
		if (json_object_object_get_ex(json, pattern, &json_misc)) {
			/* get misc string */
			if (json_object_get_string(json_misc) &&
			    strstr(json_object_get_string(json_misc),
				   match))
				break;
		}
		i++;
	} while (1);

	if (json_object_object_get_ex(json, "pkts", &json_temp))
		zebra_wrap_script_convert_stat(
			       json_object_get_string(json_temp),
			       pkts, 1000);
	else
		ret = -1;
	if (json_object_object_get_ex(json, "bytes", &json_temp))
		zebra_wrap_script_convert_stat(
			       json_object_get_string(json_temp),
			       bytes, 1024);
	else
		ret = -1;
	return ret;
}

static int zebra_wrap_script_init(struct thread_master *t)
{
	zebra_wrap_debug = 0;
	return 0;
}
