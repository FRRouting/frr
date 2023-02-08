// SPDX-License-Identifier: GPL-2.0-or-later
/* IP forward settings.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_IPFORWARD_H
#define _ZEBRA_IPFORWARD_H

#ifdef __cplusplus
extern "C" {
#endif

extern int ipforward(void);
extern int ipforward_on(void);
extern int ipforward_off(void);

extern int ipforward_ipv6(void);
extern int ipforward_ipv6_on(void);
extern int ipforward_ipv6_off(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_IPFORWARD_H */
