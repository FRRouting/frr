// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * February 22 2024, Christian Hopps <chopps@labn.net>
 *
 * Copyright (C) 2024 LabN Consulting, L.L.C.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include "command.h"
#include "keychain.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"

#include "lib/keychain_cli_clippy.c"

DEFPY_YANG_NOSH(
       key_chain,
       key_chain_cmd,
       "key chain WORD",
       "Authentication key management\n"
       "Key-chain management\n"
       "Key-chain name\n")
{
	char *xpath;
	int ret;

	xpath = asprintfrr(MTYPE_TMP,
			   "/ietf-key-chain:key-chains/key-chain[name='%s']",
			   chain);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(KEYCHAIN_NODE, xpath);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

DEFPY_YANG(
       no_key_chain,
       no_key_chain_cmd,
       "no key chain WORD",
       NO_STR
       "Authentication key management\n"
       "Key-chain management\n"
       "Key-chain name\n")
{
	char *xpath;

	xpath = asprintfrr(MTYPE_TMP,
			   "/ietf-key-chain:key-chains/key-chain[name='%s']",
			   chain);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);
	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

DEFPY_YANG_NOSH(
       key,
       key_cmd,
       "key (0-2147483647)",
       "Configure a key\n"
       "Key identifier number\n")
{
	char *xpath;
	int ret;

	xpath = asprintfrr(MTYPE_TMP, "%s/key[key-id='%s']", VTY_CURR_XPATH,
			   key_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(KEYCHAIN_KEY_NODE, xpath);
	XFREE(MTYPE_TMP, xpath);
	return ret;
}

DEFPY_YANG(
       no_key,
       no_key_cmd,
       "no key (0-2147483647)",
       NO_STR
       "Delete a key\n"
       "Key identifier number\n")
{
	char *xpath;

	xpath = asprintfrr(MTYPE_TMP, "%s/key[key-id='%s']", VTY_CURR_XPATH,
			   key_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	XFREE(MTYPE_TMP, xpath);
	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

DEFPY_YANG(
       key_string,
       key_string_cmd,
       "key-string LINE",
       "Set key string\n"
       "The key\n")
{
	nb_cli_enqueue_change(vty, "./key-string/keystring", NB_OP_CREATE, line);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
       no_key_string,
       no_key_string_cmd,
       "no key-string [LINE]",
       NO_STR
       "Unset key string\n"
       "The key\n")
{
	nb_cli_enqueue_change(vty, "./key-string/keystring", NB_OP_DESTROY, line);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
      cryptographic_algorithm,
      cryptographic_algorithm_cmd,
      "cryptographic-algorithm "
      "<md5|hmac-sha-1|hmac-sha-256|hmac-sha-384|hmac-sha-512>$algo",
      "Cryptographic-algorithm\n"
      "Use MD5 algorithm\n"
      "Use HMAC-SHA-1 algorithm\n"
      "Use HMAC-SHA-256 algorithm\n"
      "Use HMAC-SHA-384 algorithm\n"
      "Use HMAC-SHA-512 algorithm\n")
{
	nb_cli_enqueue_change(vty, "./crypto-algorithm", NB_OP_CREATE, algo);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
      no_cryptographic_algorithm,
      no_cryptographic_algorithm_cmd,
      "no cryptographic-algorithm "
      "[<md5|hmac-sha-1|hmac-sha-256|hmac-sha-384|hmac-sha-512>$algo]",
      NO_STR
      "Cryptographic-algorithm\n"
      "Use MD5 algorithm\n"
      "Use HMAC-SHA-1 algorithm\n"
      "Use HMAC-SHA-256 algorithm\n"
      "Use HMAC-SHA-384 algorithm\n"
      "Use HMAC-SHA-512 algorithm\n")
{
	nb_cli_enqueue_change(vty, "./crypto-algorithm", NB_OP_DESTROY, algo);
	return nb_cli_apply_changes(vty, NULL);
}

const char *month_name[] = {
	"january", "february", "march", "april", "may", "june", "july",
	"august", "september", "october", "november", "december", NULL
};

static int __get_month(const char *month_str)
{
	int i, len;

	len = strlen(month_str);
	if (len < 3)
		return -1;
	for (i = 1; month_name[i-1]; i++)
		if (strncasecmp(month_str, month_name[i-1], len) == 0)
			return i;
	return -1;
}


static long __timezone_offset(void)
{
	time_t now;
	struct tm *tm_now;

	time(&now);
	tm_now = localtime(&now);
	return tm_now->tm_gmtoff;
}

static int __lifetime_set(struct vty *vty, char timebuf[32],
			  const char *time_node, const char *leaf_node,
			  const char *time_str, const char *day_str,
			  const char *month_str, const char *year_str)
{
	char xpath[128];
	int month = __get_month(month_str);
	int hoff, moff;
	long offset;

	if (month < 1) {
		vty_out(vty, "Bad month value: %s\n", month_str);
		return -1;
	}

	offset = __timezone_offset();
	hoff = offset / 3600;
	if (offset < 0)
		offset = -offset;
	moff = (offset % 3600) / 60;

	snprintf(timebuf, 32, "%s-%02d-%02dT%s%+03d:%02d", year_str, month,
		 atoi(day_str), time_str, hoff, moff);
	snprintf(xpath, sizeof(xpath), "./lifetime/%s/%s", time_node, leaf_node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, timebuf);
	return 0;
}


static int key_lifetime_set(struct vty *vty, const char *time_node,
			    const char *stime_str, const char *sday_str,
			    const char *smonth_str, const char *syear_str,
			    const char *etime_str, const char *eday_str,
			    const char *emonth_str, const char *eyear_str)
{
	char time1[32];
	char time2[32];

	if (__lifetime_set(vty, time1, time_node, "start-date-time", stime_str,
			   sday_str, smonth_str, syear_str))
		return CMD_WARNING_CONFIG_FAILED;

	if (__lifetime_set(vty, time2, time_node, "end-date-time", etime_str,
			   eday_str, emonth_str, eyear_str))
		return CMD_WARNING_CONFIG_FAILED;

	return nb_cli_apply_changes(vty, NULL);
}

static int key_lifetime_duration_set(struct vty *vty, const char *time_node,
				     const char *stime_str, const char *sday_str,
				     const char *smonth_str,
				     const char *syear_str,
				     const char *duration_str)
{
	char xpath[128];
	char time[32];

	if (__lifetime_set(vty, time, time_node, "start-date-time", stime_str,
			   sday_str, smonth_str, syear_str))
		return CMD_WARNING_CONFIG_FAILED;

	/* End time. */
	snprintf(xpath, sizeof(xpath), "./lifetime/%s/duration", time_node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, duration_str);

	return nb_cli_apply_changes(vty, NULL);
}

static int key_lifetime_infinite_set(struct vty *vty, const char *time_node,
				     const char *stime_str, const char *sday_str,
				     const char *smonth_str,
				     const char *syear_str)
{
	char xpath[128];
	char time[32];

	if (__lifetime_set(vty, time, time_node, "start-date-time", stime_str,
			   sday_str, smonth_str, syear_str))
		return CMD_WARNING_CONFIG_FAILED;

	/* End time. */
	snprintf(xpath, sizeof(xpath), "./lifetime/%s/no-end-time", time_node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
       accept_lifetime_day_month_day_month,
       accept_lifetime_day_month_day_month_cmd,
       "accept-lifetime HH:MM:SS (1-31) MONTH (1993-2035) HH:MM:SS (1-31) MONTH (1993-2035)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_number_3 = 6;
	int idx_month_2 = 7;
	int idx_number_4 = 8;

	return key_lifetime_set(vty, "accept-lifetime", argv[idx_hhmmss]->arg,
				argv[idx_number]->arg, argv[idx_month]->arg,
				argv[idx_number_2]->arg, argv[idx_hhmmss_2]->arg,
				argv[idx_number_3]->arg, argv[idx_month_2]->arg,
				argv[idx_number_4]->arg);
}

DEFPY_YANG(accept_lifetime_day_month_month_day,
       accept_lifetime_day_month_month_day_cmd,
       "accept-lifetime HH:MM:SS (1-31) MONTH (1993-2035) HH:MM:SS MONTH (1-31) (1993-2035)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_month_2 = 6;
	int idx_number_3 = 7;
	int idx_number_4 = 8;

	return key_lifetime_set(vty, "accept-lifetime", argv[idx_hhmmss]->arg,
				argv[idx_number]->arg, argv[idx_month]->arg,
				argv[idx_number_2]->arg, argv[idx_hhmmss_2]->arg,
				argv[idx_number_3]->arg, argv[idx_month_2]->arg,
				argv[idx_number_4]->arg);
}

DEFPY_YANG(accept_lifetime_month_day_day_month,
       accept_lifetime_month_day_day_month_cmd,
       "accept-lifetime HH:MM:SS MONTH (1-31) (1993-2035) HH:MM:SS (1-31) MONTH (1993-2035)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_number_3 = 6;
	int idx_month_2 = 7;
	int idx_number_4 = 8;

	return key_lifetime_set(vty, "accept-lifetime", argv[idx_hhmmss]->arg,
				argv[idx_number]->arg, argv[idx_month]->arg,
				argv[idx_number_2]->arg, argv[idx_hhmmss_2]->arg,
				argv[idx_number_3]->arg, argv[idx_month_2]->arg,
				argv[idx_number_4]->arg);
}

DEFPY_YANG(accept_lifetime_month_day_month_day,
       accept_lifetime_month_day_month_day_cmd,
       "accept-lifetime HH:MM:SS MONTH (1-31) (1993-2035) HH:MM:SS MONTH (1-31) (1993-2035)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_month_2 = 6;
	int idx_number_3 = 7;
	int idx_number_4 = 8;

	return key_lifetime_set(vty, "accept-lifetime", argv[idx_hhmmss]->arg,
				argv[idx_number]->arg, argv[idx_month]->arg,
				argv[idx_number_2]->arg, argv[idx_hhmmss_2]->arg,
				argv[idx_number_3]->arg, argv[idx_month_2]->arg,
				argv[idx_number_4]->arg);
}

DEFPY_YANG(accept_lifetime_infinite_day_month,
       accept_lifetime_infinite_day_month_cmd,
       "accept-lifetime HH:MM:SS (1-31) MONTH (1993-2035) infinite",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Never expires\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;

	return key_lifetime_infinite_set(vty, "accept-lifetime",
					 argv[idx_hhmmss]->arg,
					 argv[idx_number]->arg,
					 argv[idx_month]->arg,
					 argv[idx_number_2]->arg);
}

DEFPY_YANG(accept_lifetime_infinite_month_day,
       accept_lifetime_infinite_month_day_cmd,
       "accept-lifetime HH:MM:SS MONTH (1-31) (1993-2035) infinite",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Never expires\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;

	return key_lifetime_infinite_set(vty, "accept-lifetime",
					 argv[idx_hhmmss]->arg,
					 argv[idx_number]->arg,
					 argv[idx_month]->arg,
					 argv[idx_number_2]->arg);
}

DEFPY_YANG(accept_lifetime_duration_day_month,
       accept_lifetime_duration_day_month_cmd,
       "accept-lifetime HH:MM:SS (1-31) MONTH (1993-2035) duration (1-2147483646)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;

	return key_lifetime_duration_set(vty, "accept-lifetime",
					 argv[idx_hhmmss]->arg,
					 argv[idx_number]->arg,
					 argv[idx_month]->arg,
					 argv[idx_number_2]->arg,
					 argv[idx_number_3]->arg);
}

DEFPY_YANG(accept_lifetime_duration_month_day,
       accept_lifetime_duration_month_day_cmd,
       "accept-lifetime HH:MM:SS MONTH (1-31) (1993-2035) duration (1-2147483646)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;

	return key_lifetime_duration_set(vty, "accept-lifetime",
					 argv[idx_hhmmss]->arg,
					 argv[idx_number]->arg,
					 argv[idx_month]->arg,
					 argv[idx_number_2]->arg,
					 argv[idx_number_3]->arg);
}

DEFPY_YANG(no_accept_lifetime,
       no_accept_lifetime_cmd,
       "no accept-lifetime",
       NO_STR
       "Unset accept-lifetime\n")
{
	nb_cli_enqueue_change(vty, "accept-lifetime", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	send_lifetime_day_month_day_month, send_lifetime_day_month_day_month_cmd,
	"send-lifetime HH:MM:SS (1-31) MONTH (1993-2035) HH:MM:SS (1-31) MONTH (1993-2035)",
	"Set send lifetime of the key\n"
	"Time to start\n"
	"Day of th month to start\n"
	"Month of the year to start\n"
	"Year to start\n"
	"Time to expire\n"
	"Day of th month to expire\n"
	"Month of the year to expire\n"
	"Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_number_3 = 6;
	int idx_month_2 = 7;
	int idx_number_4 = 8;

	return key_lifetime_set(vty, "send-lifetime", argv[idx_hhmmss]->arg,
				argv[idx_number]->arg, argv[idx_month]->arg,
				argv[idx_number_2]->arg, argv[idx_hhmmss_2]->arg,
				argv[idx_number_3]->arg, argv[idx_month_2]->arg,
				argv[idx_number_4]->arg);
}

DEFPY_YANG(send_lifetime_day_month_month_day,
       send_lifetime_day_month_month_day_cmd,
       "send-lifetime HH:MM:SS (1-31) MONTH (1993-2035) HH:MM:SS MONTH (1-31) (1993-2035)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_month_2 = 6;
	int idx_number_3 = 7;
	int idx_number_4 = 8;

	return key_lifetime_set(vty, "send-lifetime", argv[idx_hhmmss]->arg,
				argv[idx_number]->arg, argv[idx_month]->arg,
				argv[idx_number_2]->arg, argv[idx_hhmmss_2]->arg,
				argv[idx_number_3]->arg, argv[idx_month_2]->arg,
				argv[idx_number_4]->arg);
}

DEFPY_YANG(send_lifetime_month_day_day_month,
       send_lifetime_month_day_day_month_cmd,
       "send-lifetime HH:MM:SS MONTH (1-31) (1993-2035) HH:MM:SS (1-31) MONTH (1993-2035)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_number_3 = 6;
	int idx_month_2 = 7;
	int idx_number_4 = 8;

	return key_lifetime_set(vty, "send-lifetime", argv[idx_hhmmss]->arg,
				argv[idx_number]->arg, argv[idx_month]->arg,
				argv[idx_number_2]->arg, argv[idx_hhmmss_2]->arg,
				argv[idx_number_3]->arg, argv[idx_month_2]->arg,
				argv[idx_number_4]->arg);
}

DEFPY_YANG(send_lifetime_month_day_month_day,
       send_lifetime_month_day_month_day_cmd,
       "send-lifetime HH:MM:SS MONTH (1-31) (1993-2035) HH:MM:SS MONTH (1-31) (1993-2035)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_month_2 = 6;
	int idx_number_3 = 7;
	int idx_number_4 = 8;

	return key_lifetime_set(vty, "send-lifetime", argv[idx_hhmmss]->arg,
				argv[idx_number]->arg, argv[idx_month]->arg,
				argv[idx_number_2]->arg, argv[idx_hhmmss_2]->arg,
				argv[idx_number_3]->arg, argv[idx_month_2]->arg,
				argv[idx_number_4]->arg);
}

DEFPY_YANG(send_lifetime_infinite_day_month,
       send_lifetime_infinite_day_month_cmd,
       "send-lifetime HH:MM:SS (1-31) MONTH (1993-2035) infinite",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Never expires\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;

	return key_lifetime_infinite_set(vty, "send-lifetime",
					 argv[idx_hhmmss]->arg,
					 argv[idx_number]->arg,
					 argv[idx_month]->arg,
					 argv[idx_number_2]->arg);
}

DEFPY_YANG(send_lifetime_infinite_month_day,
       send_lifetime_infinite_month_day_cmd,
       "send-lifetime HH:MM:SS MONTH (1-31) (1993-2035) infinite",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Never expires\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;

	return key_lifetime_infinite_set(vty, "send-lifetime",
					 argv[idx_hhmmss]->arg,
					 argv[idx_number]->arg,
					 argv[idx_month]->arg,
					 argv[idx_number_2]->arg);
}

DEFPY_YANG(send_lifetime_duration_day_month,
       send_lifetime_duration_day_month_cmd,
       "send-lifetime HH:MM:SS (1-31) MONTH (1993-2035) duration (1-2147483646)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;

	return key_lifetime_duration_set(vty, "send-lifetime",
					 argv[idx_hhmmss]->arg,
					 argv[idx_number]->arg,
					 argv[idx_month]->arg,
					 argv[idx_number_2]->arg,
					 argv[idx_number_3]->arg);
}

DEFPY_YANG(send_lifetime_duration_month_day,
       send_lifetime_duration_month_day_cmd,
       "send-lifetime HH:MM:SS MONTH (1-31) (1993-2035) duration (1-2147483646)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;

	return key_lifetime_duration_set(vty, "send-lifetime",
					 argv[idx_hhmmss]->arg,
					 argv[idx_number]->arg,
					 argv[idx_month]->arg,
					 argv[idx_number_2]->arg,
					 argv[idx_number_3]->arg);
}

DEFUN (no_send_lifetime,
       no_send_lifetime_cmd,
       "no send-lifetime",
       NO_STR
       "Unset send-lifetime\n")
{
	nb_cli_enqueue_change(vty, "send-lifetime", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain
 */
void key_chains_key_chain_cli_write(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, "key chain %s\n", yang_dnode_get_string(dnode, "name"));
}

void key_chains_key_chain_cli_write_end(struct vty *vty,
					const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/description
 */
void key_chains_key_chain_description_cli_write(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults)
{
	/* Implement CLI */
	/* vty_out(vty, " description %s\n", yang_dnode_get_string(dnode)); */
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key
 */
void key_chains_key_chain_key_cli_write(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, " key %s\n", yang_dnode_get_string(dnode, "key-id"));
}

void key_chains_key_chain_key_cli_write_end(struct vty *vty,
					    const struct lyd_node *dnode)
{
	vty_out(vty, " exit\n");
}

static const char *__dnode_to_key_strftime(char *buf, size_t bufsize,
					   const struct lyd_node *lt_start_dnode)
{
	const char *timestr;
	struct lyd_node *end_node;
	struct tm tm;
	uint32_t duration;
	time_t time;
	int len, sz;
	char *s;

	s = buf;
	sz = bufsize;

	timestr = yang_dnode_get_string(lt_start_dnode, NULL);
	(void)ly_time_str2time(timestr, &time, NULL);
	localtime_r(&time, &tm);
	len = strftime(s, sz, "%T %b %e %Y", &tm);
	s += len;
	sz -= len;

	if (yang_dnode_exists(lt_start_dnode, "../no-end-time")) {
		strlcat(s, " infinite", sz);
		return buf;
	}

	end_node = yang_dnode_get(lt_start_dnode, "../duration");
	if (end_node) {
		duration = yang_dnode_get_uint32(end_node, NULL);
		snprintf(s, sz, " duration %u", (uint)duration);
		return buf;
	}

	timestr = yang_dnode_get_string(lt_start_dnode, "../end-date-time");
	(void)ly_time_str2time(timestr, &time, NULL);
	localtime_r(&time, &tm);
	strftime(s, sz, " %T %b %e %Y", &tm);
	return buf;
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/start-date-time
 */
void key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	char s[256];

	vty_out(vty, "  send-lifetime %s\n",
		__dnode_to_key_strftime(s, sizeof(s), dnode));
	vty_out(vty, "  accept-lifetime %s\n", s);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/start-date-time
 */
void key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	char s[256];

	vty_out(vty, "  send-lifetime %s\n",
		__dnode_to_key_strftime(s, sizeof(s), dnode));
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/start-date-time
 */
void key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	char s[256];

	vty_out(vty, "  accept-lifetime %s\n",
		__dnode_to_key_strftime(s, sizeof(s), dnode));
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/crypto-algorithm
 */
void key_chains_key_chain_key_crypto_algorithm_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	static const char prefix[] = "ietf-key-chain:";
	static const int prefix_len = sizeof(prefix) - 1;
	const char *name = yang_dnode_get_string(dnode, NULL);

	if (!strncmp(name, prefix, prefix_len))
		name += prefix_len;
	vty_out(vty, "  cryptographic-algorithm %s\n", name);
}

/*
 * XPath: /ietf-key-chain:key-chains/key-chain/key/key-string/keystring
 */
void key_chains_key_chain_key_key_string_keystring_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  key-string %s\n", yang_dnode_get_string(dnode, NULL));
}

static const char * const keychain_features[] = {
	"independent-send-accept-lifetime",
	NULL,
};

/* clang-format off */
const struct frr_yang_module_info ietf_key_chain_cli_info = {
	.name = "ietf-key-chain",
	.features = (const char **)keychain_features,
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain",
			.cbs = {
				.cli_show = key_chains_key_chain_cli_write,
				.cli_show_end = key_chains_key_chain_cli_write_end,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/description",
			.cbs = {
				.cli_show = key_chains_key_chain_description_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key",
			.cbs = {
				.cli_show = key_chains_key_chain_key_cli_write,
				.cli_show_end = key_chains_key_chain_key_cli_write_end,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-accept-lifetime/start-date-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_accept_lifetime_start_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/send-lifetime/start-date-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_send_lifetime_start_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/lifetime/accept-lifetime/start-date-time",
			.cbs = {
				.cli_show = key_chains_key_chain_key_lifetime_accept_lifetime_start_date_time_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/crypto-algorithm",
			.cbs = {
				.cli_show = key_chains_key_chain_key_crypto_algorithm_cli_write,
			}
		},
		{
			.xpath = "/ietf-key-chain:key-chains/key-chain/key/key-string/keystring",
			.cbs = {
				.cli_show = key_chains_key_chain_key_key_string_keystring_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

static int keychain_config_write(struct vty *vty)
{
	const struct lyd_node *dnode;
	int written = 0;

	dnode = yang_dnode_get(running_config->dnode,
			       "/ietf-key-chain:key-chains");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		written = 1;
	}
	return written;
}

static struct cmd_node keychain_node = {
	.name = "keychain",
	.node = KEYCHAIN_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-keychain)# ",
	.config_write = keychain_config_write,
};

static struct cmd_node keychain_key_node = {
	.name = "keychain key",
	.node = KEYCHAIN_KEY_NODE,
	.parent_node = KEYCHAIN_NODE,
	.prompt = "%s(config-keychain-key)# ",
};

static const struct cmd_variable_handler keychain_var_handlers[] = {
	{.varname = "key_chain", .xpath = "/ietf-key-chain:key-chains/key-chain/name" },
	{.tokenname = "KEYCHAIN_NAME", .xpath = "/ietf-key-chain:key-chains/key-chain/name" },
	{.completions = NULL}
};

void keychain_cli_init(void)
{
	/* Register handler for keychain auto config support */
	cmd_variable_handler_register(keychain_var_handlers);
	install_node(&keychain_node);
	install_node(&keychain_key_node);

	install_default(KEYCHAIN_NODE);
	install_default(KEYCHAIN_KEY_NODE);

	install_element(CONFIG_NODE, &key_chain_cmd);
	install_element(CONFIG_NODE, &no_key_chain_cmd);
	install_element(KEYCHAIN_NODE, &key_cmd);
	install_element(KEYCHAIN_NODE, &no_key_cmd);

	install_element(KEYCHAIN_NODE, &key_chain_cmd);
	install_element(KEYCHAIN_NODE, &no_key_chain_cmd);

	install_element(KEYCHAIN_KEY_NODE, &key_string_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_key_string_cmd);

	install_element(KEYCHAIN_KEY_NODE, &key_chain_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_key_chain_cmd);

	install_element(KEYCHAIN_KEY_NODE, &key_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_key_cmd);

	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_day_month_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_day_month_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_month_day_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_month_day_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_infinite_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_infinite_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_duration_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_duration_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_accept_lifetime_cmd);

	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_day_month_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_day_month_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_month_day_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_month_day_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_infinite_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_infinite_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_duration_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_duration_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_send_lifetime_cmd);
	install_element(KEYCHAIN_KEY_NODE, &cryptographic_algorithm_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_cryptographic_algorithm_cmd);
}
