/* 
 *
 * Copyright 2009-2015, LabN Consulting, L.L.C.
 *
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifndef _QUAGGA_BGP_ENCAP_H
#define _QUAGGA_BGP_ENCAP_H

extern void bgp_encap_init (void);
extern int bgp_nlri_parse_encap (struct peer *, struct attr *, struct bgp_nlri *);

#include "bgp_encap_types.h"
#endif /* _QUAGGA_BGP_ENCAP_H */
