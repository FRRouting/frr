/*
 * Zebra Script Wrapper
 * Copyright 2018 6WIND S.A.
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
#include "lib/version.h"
#include "hook.h"
#include "libfrr.h"
#include "memory.h"
#include "command.h"

#include "zebra/debug.h"
#include "zebra/rib.h"
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

/* definitions */
#define IPSET_PRE_HASH "hash:"

#define SCRIPT_NETFILTER_IPTABLES "iptables"
#define SCRIPT_NETFILTER_IPSET "ipset"
DEFINE_MTYPE_STATIC(ZEBRA, SCRIPTCACHE, "Cache Information");
static char *zebra_wrap_script_iptable_pathname;
static char *zebra_wrap_script_ipset_pathname;
static char *zebra_wrap_script_get_iptable_pathname;
static char *zebra_wrap_script_get_ipset_pathname;

static int zebra_wrap_script_config_write(struct vty *vty);

static struct cmd_node zebra_wrap_script_node = {.name = "Wrap Script",
						 .node = WRAP_SCRIPT_NODE,
						 .prompt = "",
						 .config_write = zebra_wrap_script_config_write};

#define ZEBRA_DEBUG_WRAP_SCRIPT      SCRIPT_DEBUG
static int zebra_wrap_debug;

static const struct message ip_proto_str[] = {
	{IPPROTO_TCP, "tcp"},
	{IPPROTO_UDP, "udp"},
	{IPPROTO_ICMP, "icmp"},
	{0}
};

#define WRAP_REFRESH_TIME_SECOND 5

struct zebra_wrap_iptable_json_cache {
	struct json_object *iptable_list;
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
	time_t tv_sec;
};

struct zebra_wrap_ipset_json_cache {
	struct json_object *ipset_list;
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
	time_t tv_sec;
};

static struct zebra_wrap_ipset_json_cache *ipset_json;
static struct zebra_wrap_iptable_json_cache *iptable_json;

static int zebra_wrap_script_ipset_entry_get_stat(
				struct zebra_pbr_ipset_entry *ipset,
				uint64_t *pkts, uint64_t *bytes);
static int zebra_wrap_script_iptable_get_stat(
				struct zebra_pbr_iptable *iptable,
				uint64_t *pkts, uint64_t *bytes);

static int zebra_wrap_script_init(struct thread_master *t);

static int zebra_wrap_script_iptable_update(int cmd,
					    struct zebra_pbr_iptable *iptable);
static int zebra_wrap_script_ipset_update(int cmd,
					  struct zebra_pbr_ipset *ipset);
static int zebra_wrap_script_ipset_entry_update(int cmd,
					  struct zebra_pbr_ipset_entry *ipset);
static int zebra_wrap_show_debugging(struct vty *vty);

static int zebra_wrap_script_module_init(void)
{
	hook_register(zebra_pbr_iptable_get_stat,
		      zebra_wrap_script_iptable_get_stat);
	hook_register(zebra_pbr_ipset_entry_get_stat,
		      zebra_wrap_script_ipset_entry_get_stat);
	hook_register(frr_late_init, zebra_wrap_script_init);
	hook_register(zebra_pbr_iptable_update,
		      zebra_wrap_script_iptable_update);
	hook_register(zebra_pbr_ipset_entry_update,
		      zebra_wrap_script_ipset_entry_update);
	hook_register(zebra_pbr_ipset_update,
		      zebra_wrap_script_ipset_update);
	hook_register(zebra_debug_show_debugging,
		      zebra_wrap_show_debugging);
	return 0;
}

FRR_MODULE_SETUP(
		 .name = "zebra_wrap",
		 .version = FRR_VERSION,
		 .description = "zebra wrap script module",
		 .init = zebra_wrap_script_module_init
		 );

static int zebra_wrap_sprint_port(char *str,
				 int tot_len,
				 uint16_t port,
				 uint8_t proto)
{
	char *ptr = str;
	int len_written, len = tot_len;

	len_written = snprintf(ptr, len, ",%s",
			lookup_msg(ip_proto_str, proto,
				   "NA:"));
	len -= len_written;
	ptr += len_written;
	if (port || proto == IPPROTO_ICMP) {
		if (proto == IPPROTO_ICMP) {
			char decoded_str[20];
			uint8_t icmp_type, icmp_code;

			icmp_type = (port >> 8) & 0xff;
			icmp_code = (port & 0xff);
			memset(decoded_str, 0, sizeof(decoded_str));
			sprintf(decoded_str, "%d/%d", icmp_type, icmp_code);
			len_written = snprintf(ptr, len, ":%s",
					       lookup_msg(icmp_typecode_str,
							  port, decoded_str));
		} else {
			len_written = snprintf(ptr, len, ":%d", port);
		}
		len -= len_written;
		ptr += len_written;
	}
	return tot_len - len;
}

static const char *zebra_wrap_prefix2str(union prefixconstptr pu,
					char *str, int size)
{
	const struct prefix *p = pu.p;
	char buf[PREFIX2STR_BUFFER];

	if (p->family == AF_INET && p->prefixlen == IPV4_MAX_PREFIXLEN) {
		snprintf(str, size, "%s", inet_ntop(p->family, &p->u.prefix,
						    buf, PREFIX2STR_BUFFER));
		return str;
	}
	return prefix2str(pu, str, size);
}

/* return a string identifier similar to what is available in
 * ipset list. optional_proto is here to override proto value
 * of zpi if proto value is not available
 * port value either stands for tcp/udp port or icmp typecode
 */
static void zebra_wrap_forge_ipset_identifier(char *buffer, size_t buff_len,
					     uint32_t type,
					     struct prefix *src,
					     struct prefix *dst,
					     uint16_t port,
					     uint8_t proto)
{
	size_t len = buff_len;
	char *ptr = buffer;

	if ((type == IPSET_NET_NET) ||
	    (type == IPSET_NET_PORT_NET)) {
		char buf[PREFIX_STRLEN];
		int len_temp;

		zebra_wrap_prefix2str(src,
				     buf, sizeof(buf));
		len_temp = snprintf(ptr, len, "%s", buf);
		ptr += len_temp;
		len -= len_temp;
		if (port || proto == IPPROTO_ICMP) {
			len_temp = zebra_wrap_sprint_port(ptr, len,
							 port, proto);
			ptr += len_temp;
			len -= len_temp;
		}
		zebra_wrap_prefix2str(dst,
				     buf, sizeof(buf));
		snprintf(ptr, len, ",%s", buf);
	} else if ((type == IPSET_NET) ||
		   (type == IPSET_NET_PORT)) {
		char buf[PREFIX_STRLEN];
		int len_temp;

		if (src)
			zebra_wrap_prefix2str(src, buf, sizeof(buf));
		else
			zebra_wrap_prefix2str(dst, buf, sizeof(buf));
		len_temp = snprintf(ptr, len, "%s", buf);
		ptr += len_temp;
		len -= len_temp;
		if (port || proto == IPPROTO_ICMP)
			zebra_wrap_sprint_port(ptr, len,
					      port, proto);
	}
}

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
				char temp_word[DATA_LINE_MAX + 1];

				snprintf(temp_word,
					 sizeof(temp_word),
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
				    const char *switch_to_mode_row_at)
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
			char line[11];

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
				char line[11];

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

static int zebra_wrap_script_call_only(const char *script)
{
	FILE *fp;

	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
		zlog_debug("SCRIPT : %s", script);
	fp = popen(script, "r");
	if (!fp) {
		zlog_err("SCRIPT: error calling %s", script);
		return -1;
	}
	if (pclose(fp)) {
		zlog_err("SCRIPT: error with %s: closing stream (errno %u)",
			 script, errno);
		return -1;
	}
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
	char buff[11];
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

static int zebra_wrap_script_ipset_entry_get_stat(
				struct zebra_pbr_ipset_entry *zpie,
				uint64_t *pkts, uint64_t *bytes)
{
	struct timeval tv;
	struct prefix *src = NULL, *dst = NULL;
	char json_data_str[100];
	char *ptr = json_data_str;
	size_t len = sizeof(json_data_str);
	struct zebra_pbr_ipset *zpi = zpie->backpointer;
	int ret = 0;

	monotime(&tv);
	if (!ipset_json) {
		ipset_json = XCALLOC(MTYPE_SCRIPTCACHE,
				     sizeof(struct zebra_wrap_ipset_json_cache));
		if (!ipset_json)
			return 0;
	}
	if (ipset_json->ipset_list) {
		if (strncmp(zpi->ipset_name,
			    ipset_json->ipset_name, ZEBRA_IPSET_NAME_SIZE)) {
			json_object_free(ipset_json->ipset_list);
			ipset_json->ipset_list = NULL;
			ipset_json->tv_sec = tv.tv_sec;
		} else if (tv.tv_sec - ipset_json->tv_sec > WRAP_REFRESH_TIME_SECOND) {
			json_object_free(ipset_json->ipset_list);
			ipset_json->ipset_list = NULL;
			ipset_json->tv_sec = tv.tv_sec;
		}
	}
	/* populate json table */
	if (!ipset_json->ipset_list) {
		char input[120];
		const char *members = "Members:";
		int ret = 0;

		ipset_json->ipset_list = json_object_new_object();
		/*
		 * The following call will analyse the output of 'ipset --list'
		 * command, and will return a json string format that will contain
		 * the output of previous command executed. The below comment
		 * lines explain how the translation is done
		 *
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
		 * =>
		 * "0":{"Name":"match0x39ea2d0", "Type":"hash:net,net",
		 * "Revision":"2","Header":"...", ...,"Number of entries":"2"}
		 * "1":{"data":"1.1.1.2,2.2.2.2","packets":"0","bytes":"0"}
		 * "2":{"data":"172.17.0.0/24,172.17.0.31","packets":"0","bytes":"0"}
		 */
		snprintf(input, sizeof(input),
			 "%s --list %s",
			 zebra_wrap_script_get_ipset_pathname, zpi->ipset_name);
		ret = zebra_wrap_script_column(input, 1,
						   ipset_json->ipset_list, members);
		if (ret < 0) {
			json_object_free(ipset_json->ipset_list);
			ipset_json->ipset_list = NULL;
			return 0;
		}
		ipset_json->tv_sec = tv.tv_sec;
	}
	memset(json_data_str, 0, sizeof(json_data_str));
	if (zpie->filter_bm & PBR_FILTER_SRC_IP)
		src = &(zpie->src);
	if (zpie->filter_bm & PBR_FILTER_DST_IP)
		dst = &(zpie->dst);
	memset(ptr, 0, sizeof(json_data_str));
	if ((zpi->type == IPSET_NET) ||
	    (zpi->type == IPSET_NET_NET)) {
		zebra_wrap_forge_ipset_identifier(ptr, len, zpi->type,
						 src, dst, 0, 0);
		ret = zebra_wrap_script_get_stat(ipset_json->ipset_list, "data",
						 json_data_str, pkts, bytes);
	} else if (((zpi->type == IPSET_NET_PORT) ||
		    zpi->type == IPSET_NET_PORT_NET)) {
		uint16_t port, port_min, port_max;
		uint16_t proto = 0, proto2;

		if (zpie->proto == IPPROTO_ICMP) {
			uint16_t icmp_typecode, icmp_code;
			uint16_t icmp_code_min, icmp_code_max;

			proto = zpie->proto;
			port_min = zpie->src_port_min;
			port_max = zpie->src_port_max;
			icmp_code_min = zpie->dst_port_min;
			icmp_code_max = zpie->dst_port_max;
			if (port_max == 0)
				port_max = port_min;
			if (icmp_code_max == 0)
				icmp_code_max = icmp_code_min;
			for (port = port_min; port <= port_max; port++) {
				for (icmp_code = icmp_code_min;
				     icmp_code <= icmp_code_max;
				     icmp_code++) {
					uint64_t pkts_to_add = 0, bytes_to_add = 0;

					icmp_typecode = ((port << 8) & 0xff00) +
						(icmp_code && 0xff);
					ptr = json_data_str;

					memset(ptr, 0, sizeof(json_data_str));
					zebra_wrap_forge_ipset_identifier(ptr, len,
									  zpi->type,
									  src, dst,
									  icmp_typecode,
									  proto);
					ret = zebra_wrap_script_get_stat(
									 ipset_json->ipset_list,
									 "data",
									 json_data_str,
									 &pkts_to_add,
									 &bytes_to_add);
					*pkts += pkts_to_add;
					*bytes += bytes_to_add;
				}
			}
			return ret;
		}
		if (zpie->filter_bm & PBR_FILTER_SRC_PORT) {
			port_min = zpie->src_port_min;
			port_max = zpie->src_port_max;
		} else {
			port_min = zpie->dst_port_min;
			port_max = zpie->dst_port_max;
		}
		if (port_max == 0)
			port_max = port_min;
		/* case range of ports */
		proto = (zpie->proto == 0) ? IPPROTO_TCP : zpie->proto;
		proto2 = (zpie->proto == 0) ? IPPROTO_UDP : 0;
		for (port = port_min; port <= port_max; port++) {
			uint64_t pkts_to_add = 0, bytes_to_add = 0;
			ptr = json_data_str;
			memset(ptr, 0, sizeof(json_data_str));
			zebra_wrap_forge_ipset_identifier(ptr, len,
							 zpi->type,
							 src, dst,
							 port, proto);
			ret = zebra_wrap_script_get_stat(
							 ipset_json->ipset_list,
							 "data",
							 json_data_str,
							 &pkts_to_add,
							 &bytes_to_add);
			*pkts += pkts_to_add;
			*bytes += bytes_to_add;

			if (proto2 == 0)
				continue;
			ptr = json_data_str;
			zebra_wrap_forge_ipset_identifier(ptr, len,
							 zpi->type,
							 src, dst,
							 port, proto2);
			ret += zebra_wrap_script_get_stat(
							  ipset_json->ipset_list,
							  "data",
							  json_data_str,
							  &pkts_to_add,
							  &bytes_to_add);
			*pkts += pkts_to_add;
			*bytes += bytes_to_add;
		}
	}
	return ret;
}

static int zebra_wrap_script_iptable_get_stat(
				struct zebra_pbr_iptable *iptable,
				uint64_t *pkts, uint64_t *bytes)
{
	struct timeval tv;
	int ret = 0;

	monotime(&tv);
	if (!iptable_json) {
		iptable_json = XCALLOC(MTYPE_SCRIPTCACHE,
				       sizeof(struct zebra_wrap_iptable_json_cache));
		if (!iptable_json)
			return 0;
	}
	if (iptable_json->iptable_list) {
		if (tv.tv_sec - iptable_json->tv_sec > WRAP_REFRESH_TIME_SECOND) {
			json_object_free(iptable_json->iptable_list);
			iptable_json->iptable_list = NULL;
			iptable_json->tv_sec = tv.tv_sec;
		}
	}
	/* populate json table */
	if (!iptable_json->iptable_list) {
		char input[120];

		iptable_json->iptable_list = json_object_new_object();
		snprintf(input, sizeof(input),
			 "%s -t mangle -L PREROUTING -v",
			 zebra_wrap_script_get_iptable_pathname);
		/*
		 * The following call will analyse the output of 'iptables'
		 * command, and will return a json string format that will contain
		 * the output of previous command executed. The below comment
		 * lines explain how the translation is done
		 *
		 * pkts bytes target     prot opt in     out     source destination
		 *  0     0     MARK       all --  any    any     anywhere anywhere \
		 * match-set match0x44af320 dst,dst MARK set 0x100
		 * =>
		 * "<IDx>":{ "pkts":"<X>","bytes":"<Y>"",...,"misc":"..	\
		 *  match0x<ptr1> ..."},
		 * "<IDy>":{ "pkts":"<X>","bytes":"<Y>"",...,"misc":"..	\
		 * match0x<ptr2> ..."},
		 */
		ret = zebra_wrap_script_rows(input, 1, iptable_json->iptable_list);
		if (ret < 0) {
			json_object_free(iptable_json->iptable_list);
			iptable_json->iptable_list = NULL;
			return 0;
		}
		iptable_json->tv_sec = tv.tv_sec;
	}

	ret = zebra_wrap_script_get_stat(iptable_json->iptable_list, "misc",
					 iptable->ipset_name, pkts, bytes);
	return ret;
}

/*************************************************
 * iptable
 *************************************************/
static int netlink_iptable_add_user_action(struct zebra_pbr_iptable *iptable,
					   int cmd)
{
	char buf2[100];
	int ret = 0;

	/* because MARK is not a termination rule in iptables
	 * a custom user rule is created
	 * the traffic will be marked and the accept termination
	 * rule will be done in that custom user rule
	 * - step 1 : create custom user rule
	 * - step 2 : do the mark action in custom user rule
	 * - step 3 : do the apply termination action
	 */
	if (cmd) {
		snprintf(buf2, sizeof(buf2), "%s -N %s -t mangle",
			zebra_wrap_script_iptable_pathname,
			iptable->ipset_name);
		ret = zebra_wrap_script_call_only(buf2);

		snprintf(buf2, sizeof(buf2),
			"%s -A %s -t mangle -j MARK --set-mark %d",
			zebra_wrap_script_iptable_pathname,
			iptable->ipset_name,
			iptable->fwmark);
		ret = zebra_wrap_script_call_only(buf2);

		snprintf(buf2, sizeof(buf2),
			 "%s -A %s -t mangle -j ACCEPT",
			zebra_wrap_script_iptable_pathname,
			iptable->ipset_name);
		ret = zebra_wrap_script_call_only(buf2);
	} else {
		/* - step 1 : remove the apply termination action
		 * - step 2 : remove the mark action in custom user rule
		 * - step 3 : remove custom user rule
		 */
		snprintf(buf2, sizeof(buf2),
			 "%s -D %s -t mangle -j ACCEPT",
			zebra_wrap_script_iptable_pathname,
			iptable->ipset_name);
		ret = zebra_wrap_script_call_only(buf2);

		snprintf(buf2, sizeof(buf2),
			 "%s -D %s -t mangle -j MARK --set-mark %d",
			zebra_wrap_script_iptable_pathname,
			iptable->ipset_name,
			iptable->fwmark);
		ret = zebra_wrap_script_call_only(buf2);

		snprintf(buf2, sizeof(buf2),
			 "%s -X %s -t mangle",
			zebra_wrap_script_iptable_pathname,
			iptable->ipset_name);
		ret = zebra_wrap_script_call_only(buf2);
	}
	return ret;
}

static int netlink_iptable_update_unit_2(char *buf, char *ptr,
					 int *remaining_len,
					 struct zebra_pbr_iptable *iptable,
					 char *combi, int cmd)
{
	int ret = 0;
	int len_written = 0;
	char complement_len[256];

	memset(complement_len, 0, sizeof (complement_len));
	if (iptable->tcp_flags) {
		char tcp_flag_str[64];
		char tcp_flag_mask_str[64];

		zebra_pbr_tcpflags_snprintf(tcp_flag_str,
					    sizeof(tcp_flag_str),
					    iptable->tcp_flags);
		zebra_pbr_tcpflags_snprintf(tcp_flag_mask_str,
					    sizeof(tcp_flag_mask_str),
					    iptable->tcp_mask_flags);

		len_written += snprintf(complement_len,
					sizeof(complement_len),
					"-p tcp -m tcp --tcp-flags %s %s ",
					tcp_flag_str, tcp_flag_mask_str);
	}
	if (iptable->pkt_len_min || iptable->pkt_len_max) {
		len_written += snprintf(complement_len + len_written,
					sizeof(complement_len) - len_written,
				       "-m length %s --length %d",
					iptable->filter_bm &
					MATCH_PKT_LEN_INVERSE_SET ? "!" : "",
				       iptable->pkt_len_min);
		if (iptable->pkt_len_max)
			len_written += snprintf(complement_len + len_written,
				 sizeof(complement_len) - len_written,
				 ":%d ", iptable->pkt_len_max);
		else
			len_written += snprintf(complement_len + len_written,
				 sizeof(complement_len) - len_written,
						" ");
	}
	len_written = snprintf(ptr, *remaining_len,
			       " --match-set %s %s %s",
			       iptable->ipset_name,
			       combi, complement_len);
	*remaining_len -= len_written;
	ptr += len_written;
	if (iptable->action == ZEBRA_IPTABLES_DROP) {
		len_written = snprintf(ptr, *remaining_len, " -j DROP");
		*remaining_len -= len_written;
		ptr += len_written;
	} else {
		/* because MARK is not a termination rule in iptables
		 * a custom user rule is created
		 * the traffic will be marked and the accept termination
		 * rule will be done in that custom user rule
		 * - step 1 : create custom user rule
		 * - step 2 : do the mark action in custom user rule
		 * - step 3 : do the apply termination action
		 */
		if (cmd)
			ret = netlink_iptable_add_user_action(iptable, cmd);
		len_written = snprintf(ptr, *remaining_len, " -g %s",
				       iptable->ipset_name);
		*remaining_len -= len_written;
	}
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("PBR: %s", buf);
	ret += zebra_wrap_script_call_only(buf);
	if (iptable->action == ZEBRA_IPTABLES_DROP || cmd)
		return ret;
	ret = netlink_iptable_add_user_action(iptable, cmd);
	return ret;
}

static int netlink_iptable_update_unit(int cmd,
				  struct zebra_pbr_iptable *iptable,
				  char *combi)
{
	char buf[256];
	char *ptr = buf;
	int remaining_len = sizeof(buf);
	int len_written;
	struct listnode *node;
	char *name;

	if (!iptable->nb_interface) {
		len_written = snprintf(buf, sizeof(buf),
				       "%s -t mangle -%s PREROUTING -m set",
				       zebra_wrap_script_iptable_pathname,
				       cmd ? "I":"D");
		remaining_len -= len_written;
		ptr += len_written;
		return netlink_iptable_update_unit_2(buf, ptr, &remaining_len,
						     iptable, combi, cmd);
	}

	for (ALL_LIST_ELEMENTS_RO(iptable->interface_name_list,
			       node, name)) {
		ptr = buf;
		remaining_len = sizeof(buf);
		len_written = snprintf(ptr, remaining_len,
				       "%s -i %s -t mangle -%s PREROUTING -m set",
				       zebra_wrap_script_iptable_pathname,
				       name, cmd ? "I":"D");
		ptr += len_written;
		remaining_len -= len_written;
		netlink_iptable_update_unit_2(buf, ptr, &remaining_len,
					      iptable, combi, cmd);
	}
	return 0;
}


/*
 * Form netlink message and ship it. Currently, notify status after
 * waiting for netlink status.
 */
static int zebra_wrap_script_iptable_update(int cmd,
					    struct zebra_pbr_iptable *iptable)
{
	char buf2[32];
	int ret = 0;

	if (!zebra_wrap_script_iptable_pathname) {
		zlog_err("SCRIPT: script not configured for iptable\n");
		return 0;
	}
	if (iptable->type == IPSET_NET_NET) {
		snprintf(buf2, sizeof(buf2), "src,dst");
		ret = netlink_iptable_update_unit(cmd, iptable, buf2);
	} else if (iptable->type == IPSET_NET) {
		if (iptable->filter_bm & PBR_FILTER_DST_IP)
			snprintf(buf2, sizeof(buf2), "dst");
		else
			snprintf(buf2, sizeof(buf2), "src");
		ret = netlink_iptable_update_unit(cmd, iptable, buf2);
	} else if (iptable->type == IPSET_NET_PORT) {
		char *ptr = buf2;
		int len_written;
		int remaining_len = sizeof(buf2);

		if (iptable->filter_bm & PBR_FILTER_DST_IP) {
			len_written = snprintf(ptr, remaining_len, "dst");
			ptr += len_written;
			remaining_len -= len_written;
		} else {
			len_written = snprintf(ptr, remaining_len, "src");
			ptr += len_written;
			remaining_len -= len_written;
		}
		if (iptable->filter_bm & MATCH_ICMP_SET) {
			len_written = snprintf(ptr, remaining_len, ",src");
			ptr += len_written;
			remaining_len -= len_written;
		} else if ((iptable->filter_bm & PBR_FILTER_DST_PORT) &&
		    (iptable->filter_bm & PBR_FILTER_SRC_PORT)) {
			/* iptable rule will be called twice.
			 * one for each side
			 */
			snprintf(ptr, remaining_len, ",dst");
			ret = netlink_iptable_update_unit(cmd, iptable, buf2);
			len_written = snprintf(ptr, remaining_len, ",src");
			ptr += len_written;
			remaining_len -= len_written;
		} else if (iptable->filter_bm & PBR_FILTER_DST_PORT) {
			len_written = snprintf(ptr, remaining_len, ",dst");
			ptr += len_written;
			remaining_len -= len_written;
		} else if (iptable->filter_bm & PBR_FILTER_SRC_PORT)
			snprintf(ptr, remaining_len, ",src");
		ret += netlink_iptable_update_unit(cmd, iptable, buf2);
	} else if (iptable->type == IPSET_NET_PORT_NET) {
		char *ptr = buf2;
		int len_written;
		int remaining_len = sizeof(buf2);

		len_written = snprintf(ptr, remaining_len, "src");
		ptr += len_written;
		remaining_len -= len_written;

		if (iptable->filter_bm & MATCH_ICMP_SET) {
			len_written = snprintf(ptr, remaining_len, ",src");
			ptr += len_written;
			remaining_len -= len_written;
		} else if ((iptable->filter_bm & PBR_FILTER_DST_PORT) &&
		    (iptable->filter_bm & PBR_FILTER_SRC_PORT)) {
			snprintf(ptr, remaining_len, ",dst,dst");
			ret = netlink_iptable_update_unit(cmd, iptable, buf2);
			len_written = snprintf(ptr, remaining_len, ",src");
			ptr += len_written;
			remaining_len -= len_written;
		} else if (iptable->filter_bm & PBR_FILTER_DST_PORT) {
			len_written = snprintf(ptr, remaining_len, ",dst");
			ptr += len_written;
			remaining_len -= len_written;
		} else if (iptable->filter_bm & PBR_FILTER_SRC_PORT) {
			len_written = snprintf(ptr, remaining_len, ",src");
			ptr += len_written;
			remaining_len -= len_written;
		}
		snprintf(ptr, remaining_len, ",dst");
		ret += netlink_iptable_update_unit(cmd, iptable, buf2);
	}
	return !ret ? 1 : 0;
}

DEFUN (zebra_wrap_script_iptable,
       zebra_wrap_script_iptable_cmd,
       "wrap script iptable LINE...",
       "Wrapping utilities\n"
       "Use an external script\n"
       "IPtable utility\n"
       "path of iptable script utility \n")
{
	int idx = 3;

	if (zebra_wrap_script_iptable_pathname) {
		XFREE(MTYPE_TMP, zebra_wrap_script_iptable_pathname);
		zebra_wrap_script_iptable_pathname = NULL;
	}
	zebra_wrap_script_iptable_pathname = argv_concat(argv, argc, idx);
	return CMD_SUCCESS;
}

DEFUN (zebra_wrap_script_no_iptable,
       zebra_wrap_script_no_iptable_cmd,
       "no wrap script iptable",
       NO_STR
       "Wrapping utilities\n"
       "Use an external script\n"
       "IPtable utility\n")
{
	XFREE(MTYPE_TMP, zebra_wrap_script_iptable_pathname);
	zebra_wrap_script_iptable_pathname = NULL;
	return CMD_SUCCESS;
}

DEFUN (zebra_wrap_script_get_iptable,
       zebra_wrap_script_get_iptable_cmd,
       "wrap script get iptable LINE...",
       "Wrapping utilities\n"
       "Use an external script\n"
       "Get Context\n"
       "IPtable utility\n"
       "path of iptable script utility \n")
{
	int idx = 4;

	if (zebra_wrap_script_get_iptable_pathname) {
		XFREE(MTYPE_TMP, zebra_wrap_script_get_iptable_pathname);
		zebra_wrap_script_get_iptable_pathname = NULL;
	}
	zebra_wrap_script_get_iptable_pathname = argv_concat(argv, argc, idx);
	return CMD_SUCCESS;
}

DEFUN (zebra_wrap_script_no_get_iptable,
       zebra_wrap_script_no_get_iptable_cmd,
       "no wrap script get iptable",
       NO_STR
       "Wrapping utilities\n"
       "Use an external script\n"
       "Get Context\n"
       "IPtable utility\n")
{
	XFREE(MTYPE_TMP, zebra_wrap_script_get_iptable_pathname);
	zebra_wrap_script_get_iptable_pathname = NULL;
	return CMD_SUCCESS;
}

/*************************************************
 * ipset
 *************************************************/

/*
 * Form netlink message and ship it. Currently, notify status after
 * waiting for netlink status.
 */
static int zebra_wrap_script_ipset_update(int cmd,
					  struct zebra_pbr_ipset *ipset)
{
	char buf[256];
	int ret = 0;

	if (!zebra_wrap_script_ipset_pathname) {
		zlog_err("SCRIPT: script not configured for ipset\n");
		return 0;
	}
	if (cmd) {
		snprintf(buf, sizeof(buf),
			 "ipset create %s %s%s counters",
			 ipset->ipset_name, IPSET_PRE_HASH,
			 zebra_pbr_ipset_type2str(ipset->type));
	} else
		snprintf(buf, sizeof(buf),
			"ipset destroy %s",
			ipset->ipset_name);
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("PBR: %s", buf);
	ret = zebra_wrap_script_call_only(buf);
	return !ret ? 1 : 0;
}

static int netlink_ipset_entry_update_unit(int cmd,
					   struct zebra_pbr_ipset_entry *ipset,
					   char *buf)
{
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("PBR: %s", buf);
	return zebra_wrap_script_call_only(buf);
}

static int netlink_ipset_icmp_port(int cmd,
				    struct zebra_pbr_ipset_entry *ipset,
				    struct zebra_pbr_ipset *bp,
				    char *psrc, char *pdst)
{
	uint16_t icmp_typecode, icmp_code, icmp_type;
	uint16_t icmp_code_min, icmp_code_max;
	uint16_t icmp_type_min, icmp_type_max;
	char *ptr_to_icmp_typecode, *ptr;
	char buf[256];
	int ret = 0;

	if (ipset->proto != IPPROTO_ICMP)
		return -1;

	icmp_type_min = ipset->src_port_min;
	icmp_type_max = ipset->src_port_max;
	icmp_code_min = ipset->dst_port_min;
	icmp_code_max = ipset->dst_port_max;
	if (icmp_type_max == 0)
		icmp_type_max = icmp_type_min;
	if (icmp_code_max == 0)
		icmp_code_max = icmp_code_min;
	for (icmp_type = icmp_type_min; icmp_type <= icmp_type_max; icmp_type++) {
		for (icmp_code = icmp_code_min;
		     icmp_code <= icmp_code_max;
		     icmp_code++) {
			char decoded_str[12];

			memset(decoded_str, 0, sizeof(decoded_str));
			snprintf(decoded_str, sizeof(decoded_str), "%u/%u", icmp_type, icmp_code);
			icmp_typecode = ((uint8_t)(icmp_type) << 8) +
				(uint8_t)icmp_code;

			ptr_to_icmp_typecode =
				(char *)lookup_msg(icmp_typecode_str,
						   icmp_typecode,
						   decoded_str);
			ptr = buf;
			memset(ptr, 0, sizeof(buf));
			if (bp->type == IPSET_NET_PORT)
				snprintf(ptr, sizeof(buf), "%s %s %s %s,icmp:%s",
					 zebra_wrap_script_ipset_pathname,
					 cmd ? "add" : "del",
					 bp->ipset_name,
					 pdst == NULL ? psrc : pdst,
					 ptr_to_icmp_typecode);
			else
				snprintf(ptr, sizeof(buf), "%s %s %s %s,icmp:%s,%s",
					 zebra_wrap_script_ipset_pathname,
					 cmd ? "add" : "del",
					 bp->ipset_name,
					 psrc, ptr_to_icmp_typecode, pdst);
			ret = netlink_ipset_entry_update_unit(cmd, ipset, buf);
		}
	}
	return ret;
}

static void netlink_ipset_entry_port(char *strtofill, int lenstr,
				     uint32_t filter_bm,
				     uint16_t port_min, uint16_t port_max)
{
	if (port_max)
		snprintf(strtofill, lenstr, "%d-%d",
			port_min, port_max);
	else
		snprintf(strtofill, lenstr, "%d",
			port_min);
}

/*
 * Form netlink message and ship it. Currently, notify status after
 * waiting for netlink status.
 */
static int zebra_wrap_script_ipset_entry_update(int cmd,
					struct zebra_pbr_ipset_entry *ipset)
{
	char buf[256];
	char buf_src[PREFIX2STR_BUFFER];
	char buf_dst[PREFIX2STR_BUFFER];
	char *psrc = NULL, *pdst = NULL;
	struct zebra_pbr_ipset *bp;
	uint16_t port = 0;
	uint16_t port_max = 0;
	int ret = 0;

	if (!zebra_wrap_script_ipset_pathname) {
		zlog_err("SCRIPT: script not configured for ipset\n");
		return 0;
	}
	if (ipset->filter_bm & PBR_FILTER_SRC_PORT)
		port = ipset->src_port_min;
	else if (ipset->filter_bm & PBR_FILTER_DST_PORT)
		port = ipset->dst_port_min;
	if (ipset->filter_bm & PBR_FILTER_SRC_PORT_RANGE)
		port_max = ipset->src_port_max;
	else if (ipset->filter_bm & PBR_FILTER_DST_PORT_RANGE)
		port_max = ipset->dst_port_max;
	if (ipset->filter_bm & PBR_FILTER_SRC_IP) {
		psrc = (char *)prefix2str(&ipset->src,
					  buf_src,
					  PREFIX2STR_BUFFER);
		if (psrc == NULL)
			return 0;
	}
	if (ipset->filter_bm & PBR_FILTER_DST_IP) {
		pdst = (char *)prefix2str(&ipset->dst,
					  buf_dst,
					  PREFIX2STR_BUFFER);
		if (pdst == NULL)
			return 0;
	}
	bp = ipset->backpointer;
	if (!bp)
		return 0;
	if (bp->type == IPSET_NET_NET) {
		snprintf(buf, sizeof(buf), "%s %s %s %s,%s",
			zebra_wrap_script_ipset_pathname,
			cmd ? "add" : "del",
			bp->ipset_name,
			psrc, pdst);
		ret = netlink_ipset_entry_update_unit(cmd, ipset, buf);
	} else if (bp->type == IPSET_NET) {
		snprintf(buf, sizeof(buf), "%s %s %s %s",
			zebra_wrap_script_ipset_pathname,
			cmd ? "add" : "del",
			bp->ipset_name,
			pdst == NULL ? psrc : pdst);
		ret = netlink_ipset_entry_update_unit(cmd, ipset, buf);
	} else if (bp->type == IPSET_NET_PORT) {
		char strtofill[32];

		if (ipset->proto == IPPROTO_ICMP)
			ret += netlink_ipset_icmp_port(cmd, ipset, bp,
						psrc, pdst);
		else
			netlink_ipset_entry_port(strtofill, sizeof(strtofill),
						 ipset->filter_bm,
						 port, port_max);
		/* apply it to udp and tcp */
		if (!(ipset->filter_bm & PBR_FILTER_PROTO)) {
			snprintf(buf, sizeof(buf), "%s %s %s %s,udp:%s",
				zebra_wrap_script_ipset_pathname,
				cmd ? "add" : "del",
				bp->ipset_name,
				pdst == NULL ? psrc : pdst, strtofill);
			ret = netlink_ipset_entry_update_unit(cmd, ipset, buf);
			snprintf(buf, sizeof(buf), "%s %s %s %s,tcp:%s",
				zebra_wrap_script_ipset_pathname,
				cmd ? "add" : "del",
				bp->ipset_name,
				pdst == NULL ? psrc : pdst, strtofill);
			ret += netlink_ipset_entry_update_unit(cmd, ipset, buf);
		} else if (ipset->proto != IPPROTO_ICMP) {
			snprintf(buf, sizeof(buf), "%s %s %s %s,%d:%s",
				 zebra_wrap_script_ipset_pathname,
				 cmd ? "add" : "del",
				 bp->ipset_name,
				 pdst == NULL ? psrc : pdst, ipset->proto,
				 strtofill);
			ret = netlink_ipset_entry_update_unit(cmd, ipset, buf);
		}
	} else if (bp->type == IPSET_NET_PORT_NET) {
		char strtofill[32];

		if (ipset->proto == IPPROTO_ICMP)
			ret += netlink_ipset_icmp_port(cmd, ipset, bp,
						psrc, pdst);
		else
			netlink_ipset_entry_port(strtofill, sizeof(strtofill),
						 ipset->filter_bm,
						 port, port_max);
		/* apply it to udp and tcp */
		if (!(ipset->filter_bm & PBR_FILTER_PROTO)) {
			snprintf(buf, sizeof(buf), "%s %s %s %s,tcp:%s,%s",
				zebra_wrap_script_ipset_pathname,
				cmd ? "add" : "del",
				bp->ipset_name,
				psrc, strtofill, pdst);
			ret = netlink_ipset_entry_update_unit(cmd, ipset, buf);
			snprintf(buf, sizeof(buf), "%s %s %s %s,udp:%s,%s",
				zebra_wrap_script_ipset_pathname,
				cmd ? "add" : "del",
				bp->ipset_name,
				psrc, strtofill, pdst);
			ret += netlink_ipset_entry_update_unit(cmd, ipset, buf);
		} else if (ipset->proto != IPPROTO_ICMP) {
			snprintf(buf, sizeof(buf), "%s %s %s %s,%d:%s,%s",
				zebra_wrap_script_ipset_pathname,
				cmd ? "add" : "del",
				bp->ipset_name,
				psrc, ipset->proto, strtofill, pdst);
			ret = netlink_ipset_entry_update_unit(cmd, ipset, buf);
		}
	}
	return !ret ? 1 : 0;
}

DEFUN (zebra_wrap_script_ipset,
       zebra_wrap_script_ipset_cmd,
       "wrap script ipset LINE...",
       "Wrapping utilities\n"
       "Use an external script\n"
       "IPset utility\n"
       "path of ipset script utility \n")
{
	int idx = 3;

	if (zebra_wrap_script_ipset_pathname) {
		XFREE(MTYPE_TMP, zebra_wrap_script_ipset_pathname);
		zebra_wrap_script_ipset_pathname = NULL;
	}
	zebra_wrap_script_ipset_pathname = argv_concat(argv, argc, idx);
	return CMD_SUCCESS;
}

DEFUN (zebra_wrap_script_no_ipset,
       zebra_wrap_script_no_ipset_cmd,
       "no wrap script ipset",
       NO_STR
       "Wrapping utilities\n"
       "Use an external script\n"
       "IPset utility\n")
{
	XFREE(MTYPE_TMP, zebra_wrap_script_ipset_pathname);
	zebra_wrap_script_ipset_pathname = NULL;
	return CMD_SUCCESS;
}

DEFUN (zebra_wrap_script_get_ipset,
       zebra_wrap_script_get_ipset_cmd,
       "wrap script get ipset LINE...",
       "Wrapping utilities\n"
       "Use an external script\n"
       "Get Context\n"
       "IPset utility\n"
       "path of ipset script utility \n")
{
	int idx = 4;

	if (zebra_wrap_script_get_ipset_pathname) {
		XFREE(MTYPE_TMP, zebra_wrap_script_get_ipset_pathname);
		zebra_wrap_script_get_ipset_pathname = NULL;
	}
	zebra_wrap_script_get_ipset_pathname = argv_concat(argv, argc, idx);
	return CMD_SUCCESS;
}

DEFUN (zebra_wrap_script_no_get_ipset,
       zebra_wrap_script_no_get_ipset_cmd,
       "no wrap script get ipset",
       NO_STR
       "Wrapping utilities\n"
       "Use an external script\n"
       "Get Context\n"
       "IPset utility\n")
{
	XFREE(MTYPE_TMP, zebra_wrap_script_get_ipset_pathname);
	zebra_wrap_script_get_ipset_pathname = NULL;
	return CMD_SUCCESS;
}

/*************************************************
 * ipset, iptable general
 *************************************************/

static int zebra_wrap_script_config_write(struct vty *vty)
{
	int ret = 0;

	if (zebra_wrap_script_iptable_pathname &&
	    strncmp(zebra_wrap_script_iptable_pathname,
		    SCRIPT_NETFILTER_IPTABLES,
		    strlen(zebra_wrap_script_iptable_pathname))) {
		vty_out(vty, "wrap script iptable %s\n",
			zebra_wrap_script_iptable_pathname);
		ret++;
	}
	if (zebra_wrap_script_ipset_pathname &&
	    strncmp(zebra_wrap_script_ipset_pathname,
		    SCRIPT_NETFILTER_IPSET,
		    strlen(zebra_wrap_script_ipset_pathname))) {
		vty_out(vty, "wrap script ipset %s\n",
			zebra_wrap_script_ipset_pathname);
		ret++;
	}
	if (zebra_wrap_script_get_iptable_pathname &&
	    strncmp(zebra_wrap_script_get_iptable_pathname,
		    SCRIPT_NETFILTER_IPTABLES,
		    strlen(zebra_wrap_script_iptable_pathname))) {
		vty_out(vty, "wrap script get iptable %s\n",
			zebra_wrap_script_get_iptable_pathname);
		ret++;
	}
	if (zebra_wrap_script_get_ipset_pathname &&
	    strncmp(zebra_wrap_script_get_ipset_pathname,
		    SCRIPT_NETFILTER_IPSET,
		    strlen(zebra_wrap_script_get_ipset_pathname))) {
		vty_out(vty, "wrap script get ipset %s\n",
			zebra_wrap_script_get_ipset_pathname);
		ret++;
	}
	return ret;
}

static int zebra_wrap_show_debugging(struct vty *vty)
{
	if (zebra_wrap_debug) {
		vty_out(vty, "  Zebra Wrap debugging is on\n");
		return 1;
	}
	return 0;
}

DEFUN (debug_zebra_wrap_script,
       debug_zebra_wrap_script_cmd,
       "debug zebra wrap",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra wrap info\n")
{
	SET_FLAG(zebra_wrap_debug, ZEBRA_DEBUG_WRAP_SCRIPT);
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_wrap_script,
       no_debug_zebra_wrap_script_cmd,
       "no debug zebra wrap",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra wrap info\n")
{
	zebra_wrap_debug = 0;
	return CMD_SUCCESS;
}

static int zebra_wrap_script_init(struct thread_master *t)
{
	zebra_wrap_debug = 0;

	zebra_wrap_script_iptable_pathname = XSTRDUP(MTYPE_TMP, SCRIPT_NETFILTER_IPTABLES);
	zebra_wrap_script_get_iptable_pathname = XSTRDUP(MTYPE_TMP, SCRIPT_NETFILTER_IPTABLES);
	zebra_wrap_script_ipset_pathname = XSTRDUP(MTYPE_TMP, SCRIPT_NETFILTER_IPSET);
	zebra_wrap_script_get_ipset_pathname = XSTRDUP(MTYPE_TMP, SCRIPT_NETFILTER_IPSET);

	install_element(CONFIG_NODE, &zebra_wrap_script_iptable_cmd);
	install_element(CONFIG_NODE, &zebra_wrap_script_get_iptable_cmd);
	install_element(CONFIG_NODE, &zebra_wrap_script_ipset_cmd);
	install_element(CONFIG_NODE, &zebra_wrap_script_get_ipset_cmd);
	install_element(CONFIG_NODE, &zebra_wrap_script_no_iptable_cmd);
	install_element(CONFIG_NODE, &zebra_wrap_script_no_get_iptable_cmd);
	install_element(CONFIG_NODE, &zebra_wrap_script_no_ipset_cmd);
	install_element(CONFIG_NODE, &zebra_wrap_script_no_get_ipset_cmd);
	install_node(&zebra_wrap_script_node);
	install_element(ENABLE_NODE, &debug_zebra_wrap_script_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_wrap_script_cmd);
	install_element(CONFIG_NODE, &debug_zebra_wrap_script_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_wrap_script_cmd);

	return 0;
}
