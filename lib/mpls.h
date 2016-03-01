/*
 * MPLS definitions
 * Copyright 2015 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _QUAGGA_MPLS_H
#define _QUAGGA_MPLS_H

/* Well-known MPLS label values (RFC 3032 etc). */
#define MPLS_V4_EXP_NULL_LABEL             0
#define MPLS_RA_LABEL                      1
#define MPLS_V6_EXP_NULL_LABEL             2
#define MPLS_IMP_NULL_LABEL                3
#define MPLS_ENTROPY_LABEL_INDICATOR       7
#define MPLS_GAL_LABEL                     13
#define MPLS_OAM_ALERT_LABEL               14
#define MPLS_EXTENSION_LABEL               15

/* Minimum and maximum label values */
#define MPLS_MIN_RESERVED_LABEL            0
#define MPLS_MAX_RESERVED_LABEL            15
#define MPLS_MIN_UNRESERVED_LABEL          16
#define MPLS_MAX_UNRESERVED_LABEL          1048575

#define IS_MPLS_RESERVED_LABEL(label) \
        (label >= MPLS_MIN_RESERVED_LABEL && label <= MPLS_MAX_RESERVED_LABEL)

#define IS_MPLS_UNRESERVED_LABEL(label) \
        (label >= MPLS_MIN_UNRESERVED_LABEL && label <= MPLS_MAX_UNRESERVED_LABEL)

/* Definitions for a MPLS label stack entry (RFC 3032). This encodes the
 * label, EXP, BOS and TTL fields.
 */
typedef unsigned int mpls_lse_t;

#define MPLS_LS_LABEL_MASK             0xFFFFF000
#define MPLS_LS_LABEL_SHIFT            12
#define MPLS_LS_EXP_MASK               0x00000E00
#define MPLS_LS_EXP_SHIFT              9
#define MPLS_LS_S_MASK                 0x00000100
#define MPLS_LS_S_SHIFT                8
#define MPLS_LS_TTL_MASK               0x000000FF
#define MPLS_LS_TTL_SHIFT              0

#define MPLS_LABEL_VALUE(lse) \
        ((lse & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT)
#define MPLS_LABEL_EXP(lse) \
        ((lse & MPLS_LS_EXP_MASK) >> MPLS_LS_EXP_SHIFT)
#define MPLS_LABEL_BOS(lse) \
        ((lse & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT)
#define MPLS_LABEL_TTL(lse) \
        ((lse & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT)

#define IS_MPLS_LABEL_BOS(ls)          (MPLS_LABEL_BOS(ls) == 1)

#define MPLS_LABEL_LEN_BITS            20

/* MPLS label value as a 32-bit (mostly we only care about the label value). */
typedef unsigned int mpls_label_t;

#define MPLS_INVALID_LABEL                 0xFFFFFFFF

/* Functions for basic label operations. */

/* Encode a label stack entry from fields; convert to network byte-order as
 * the Netlink interface expects MPLS labels to be in this format.
 */
static inline mpls_lse_t
mpls_lse_encode (mpls_label_t label, u_int32_t ttl,
                 u_int32_t exp, u_int32_t bos)
{
  mpls_lse_t lse;
  lse = htonl ((label << MPLS_LS_LABEL_SHIFT) |
               (exp << MPLS_LS_EXP_SHIFT) |
               (bos ? (1 << MPLS_LS_S_SHIFT) : 0) |
               (ttl << MPLS_LS_TTL_SHIFT));
  return lse;
}

/* Extract the fields from a label stack entry after converting to host-byte
 * order. This is expected to be called only for messages received over the
 * Netlink interface.
 */
static inline void
mpls_lse_decode (mpls_lse_t lse, mpls_label_t *label,
                 u_int32_t *ttl, u_int32_t *exp, u_int32_t *bos)
{
  mpls_lse_t local_lse;

  local_lse = ntohl (lse);
  *label = MPLS_LABEL_VALUE(local_lse);
  *exp = MPLS_LABEL_EXP(local_lse);
  *bos = MPLS_LABEL_BOS(local_lse);
  *ttl = MPLS_LABEL_TTL(local_lse);
}


/* Printable string for labels (with consideration for reserved values). */
static inline char *
label2str (mpls_label_t label, char *buf, int len)
{
  switch(label) {
  case MPLS_V4_EXP_NULL_LABEL:
    strncpy(buf, "IPv4 Explicit Null", len);
    return(buf);
    break;
  case MPLS_RA_LABEL:
    strncpy(buf, "Router Alert", len);
    return(buf);
    break;
  case MPLS_V6_EXP_NULL_LABEL:
    strncpy(buf, "IPv6 Explict Null", len);
    return(buf);
    break;
  case MPLS_IMP_NULL_LABEL:
    strncpy(buf, "implicit-null", len);
    return(buf);
    break;
  case MPLS_ENTROPY_LABEL_INDICATOR:
    strncpy(buf, "Entropy Label Indicator", len);
    return(buf);
    break;
  case MPLS_GAL_LABEL:
    strncpy(buf, "Generic Associated Channel", len);
    return(buf);
    break;
  case MPLS_OAM_ALERT_LABEL:
    strncpy(buf, "OAM Alert", len);
    return(buf);
    break;
  case MPLS_EXTENSION_LABEL:
    strncpy(buf, "Extension", len);
    return(buf);
    break;
  case 4:
  case 5:
  case 6:
  case 8:
  case 9:
  case 10:
  case 11:
  case 12:
    strncpy(buf, "Reserved", len);
    return(buf);
    break;
  default:
    sprintf(buf, "%u", label);
    return(buf);
  }

  strncpy(buf, "Error", len);
  return(buf);
}

/* constants used by ldpd */
#define MPLS_LABEL_IPV4NULL	0               /* IPv4 Explicit NULL Label */
#define MPLS_LABEL_RTALERT	1               /* Router Alert Label       */
#define MPLS_LABEL_IPV6NULL	2               /* IPv6 Explicit NULL Label */
#define MPLS_LABEL_IMPLNULL	3               /* Implicit NULL Label      */
/*      MPLS_LABEL_RESERVED	4-15 */		/* Values 4-15 are reserved */
#define MPLS_LABEL_RESERVED_MAX 15
#define MPLS_LABEL_MAX		((1 << 20) - 1)

#endif
