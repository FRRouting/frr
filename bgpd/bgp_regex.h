// SPDX-License-Identifier: GPL-2.0-or-later
/* AS regular expression routine
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _FRR_BGP_REGEX_H
#define _FRR_BGP_REGEX_H

#include <zebra.h>

struct frregex;

extern void bgp_regex_free(struct frregex *regex);
extern struct frregex *bgp_regcomp(const char *str);
extern int bgp_regexec(struct frregex *regex, struct aspath *aspath);

#endif /* _FRR_BGP_REGEX_H */
