// SPDX-License-Identifier: GPL-2.0-or-later
/* AS regular expression routine
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "log.h"
#include "command.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"

#include "bgpd.h"
#include "bgp_aspath.h"
#include "bgp_regex.h"

/* Character `_' has special mean.  It represents [,{}() ] and the
   beginning of the line(^) and the end of the line ($).

   (^|[,{}() ]|$) */

regex_t *bgp_regcomp(const char *regstr)
{
	/* Convert _ character to generic regular expression. */
	int i, j;
	int len;
	int magic = 0;
	char *magic_str;
	char magic_regexp[] = "(^|[,{}() ]|$)";
	int ret;
	regex_t *regex;

	len = strlen(regstr);
	for (i = 0; i < len; i++)
		if (regstr[i] == '_')
			magic++;

	magic_str = XMALLOC(MTYPE_TMP, len + (14 * magic) + 1);

	for (i = 0, j = 0; i < len; i++) {
		if (regstr[i] == '_') {
			memcpy(magic_str + j, magic_regexp,
			       strlen(magic_regexp));
			j += strlen(magic_regexp);
		} else
			magic_str[j++] = regstr[i];
	}
	magic_str[j] = '\0';

	regex = XMALLOC(MTYPE_BGP_REGEXP, sizeof(regex_t));

	ret = regcomp(regex, magic_str, REG_EXTENDED | REG_NOSUB);

	XFREE(MTYPE_TMP, magic_str);

	if (ret != 0) {
		XFREE(MTYPE_BGP_REGEXP, regex);
		return NULL;
	}

	return regex;
}

int bgp_regexec(regex_t *regex, struct aspath *aspath)
{
	return regexec(regex, aspath->str, 0, NULL, 0);
}

void bgp_regex_free(regex_t *regex)
{
	regfree(regex);
	XFREE(MTYPE_BGP_REGEXP, regex);
}
