/*
 * Copyright (C) 1999 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
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

#ifndef OSPF6_NETWORK_H
#define OSPF6_NETWORK_H



/* Function Prototypes */
void iov_clear (struct iovec *, size_t);
int iov_count (struct iovec *);
int iov_totallen (struct iovec *);
void *iov_prepend (int, struct iovec *, size_t);
void *iov_append (int, struct iovec *, size_t);
void *iov_attach_last (struct iovec *, void *, size_t);
void *iov_detach_first (struct iovec *);
int iov_free (int, struct iovec *, u_int, u_int);
void iov_trim_head (int, struct iovec *);
void iov_free_all (int, struct iovec *);
void iov_copy_all (struct iovec *, struct iovec *, size_t);

int ospf6_serv_sock ();
int ospf6_join_allspfrouters (u_int);
void ospf6_leave_allspfrouters (u_int);
void ospf6_join_alldrouters (u_int);
void ospf6_leave_alldrouters (u_int);
void ospf6_set_reuseaddr ();
void ospf6_reset_mcastloop ();
void ospf6_set_pktinfo ();
void ospf6_set_checksum ();

void ospf6_sendmsg (struct in6_addr *, struct in6_addr *,
                    unsigned int *, struct iovec *);
void ospf6_recvmsg (struct in6_addr *, struct in6_addr *,
                    unsigned int *, struct iovec *);
void ospf6_recvmsg_peek (struct in6_addr *, struct in6_addr *,
                         unsigned int *, struct iovec *);

#endif /* OSPF6_NETWORK_H */

