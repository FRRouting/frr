/*
 * IS-IS Rout(e)ing protocol - isis_network.c   
 *
 * Copyright (C) 2001,2002    Sampo Saaristo
 *                            Tampere University of Technology      
 *                            Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <zebra.h>
#ifdef GNU_LINUX
#include <net/ethernet.h>	/* the L2 protocols */
#else
#include <net/if.h>
#include <netinet/if_ether.h>
#endif

#include "log.h"
#include "stream.h"
#include "if.h"

#include "isisd/dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isisd.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_network.h"

#include "privs.h"

extern struct zebra_privs_t isisd_privs;

/*
 * On linux we can use the packet(7) sockets, in other OSs we have to do with
 * Berkley Packet Filter (BPF). Please tell me if you can think of a better 
 * way...
 */
#ifdef GNU_LINUX
#include <netpacket/packet.h>
#else
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
struct bpf_insn llcfilter[] = {
  BPF_STMT (BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN),	/* check first byte */
  BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, ISO_SAP, 0, 5),
  BPF_STMT (BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + 1),
  BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, ISO_SAP, 0, 3),	/* check second byte */
  BPF_STMT (BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + 2),
  BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, 0x03, 0, 1),	/* check third byte */
  BPF_STMT (BPF_RET + BPF_K, (u_int) - 1),
  BPF_STMT (BPF_RET + BPF_K, 0)
};
int readblen = 0;
u_char *readbuff = NULL;
#endif /* GNU_LINUX */

/*
 * Table 9 - Architectural constans for use with ISO 8802 subnetworks
 * ISO 10589 - 8.4.8
 */

u_char ALL_L1_ISS[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x14 };
u_char ALL_L2_ISS[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x15 };
u_char ALL_ISS[6] = { 0x09, 0x00, 0x2B, 0x00, 0x00, 0x05 };
u_char ALL_ESS[6] = { 0x09, 0x00, 0x2B, 0x00, 0x00, 0x04 };

#ifdef GNU_LINUX
static char discard_buff[8192];
#endif
static char sock_buff[8192];

/*
 * if level is 0 we are joining p2p multicast
 * FIXME: and the p2p multicast being ???
 */
#ifdef GNU_LINUX
int
isis_multicast_join (int fd, int registerto, int if_num)
{
  struct packet_mreq mreq;

  memset (&mreq, 0, sizeof (mreq));
  mreq.mr_ifindex = if_num;
  if (registerto)
    {
      mreq.mr_type = PACKET_MR_MULTICAST;
      mreq.mr_alen = ETH_ALEN;
      if (registerto == 1)
	memcpy (&mreq.mr_address, ALL_L1_ISS, ETH_ALEN);
      else if (registerto == 2)
	memcpy (&mreq.mr_address, ALL_L2_ISS, ETH_ALEN);
      else if (registerto == 3)
	memcpy (&mreq.mr_address, ALL_ISS, ETH_ALEN);
      else
	memcpy (&mreq.mr_address, ALL_ESS, ETH_ALEN);

    }
  else
    {
      mreq.mr_type = PACKET_MR_ALLMULTI;
    }
#ifdef EXTREME_DEBUG
  zlog_debug ("isis_multicast_join(): fd=%d, reg_to=%d, if_num=%d, "
	      "address = %02x:%02x:%02x:%02x:%02x:%02x",
	      fd, registerto, if_num, mreq.mr_address[0], mreq.mr_address[1],
	      mreq.mr_address[2], mreq.mr_address[3], mreq.mr_address[4],
	      mreq.mr_address[5]);
#endif /* EXTREME_DEBUG */
  if (setsockopt (fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
		  sizeof (struct packet_mreq)))
    {
      zlog_warn ("isis_multicast_join(): setsockopt(): %s", safe_strerror (errno));
      return ISIS_WARNING;
    }

  return ISIS_OK;
}

int
open_packet_socket (struct isis_circuit *circuit)
{
  struct sockaddr_ll s_addr;
  int fd, retval = ISIS_OK;

  fd = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_ALL));
  if (fd < 0)
    {
      zlog_warn ("open_packet_socket(): socket() failed %s",
		 safe_strerror (errno));
      return ISIS_WARNING;
    }

  /*
   * Bind to the physical interface
   */
  memset (&s_addr, 0, sizeof (struct sockaddr_ll));
  s_addr.sll_family = AF_PACKET;
  s_addr.sll_protocol = htons (ETH_P_ALL);
  s_addr.sll_ifindex = circuit->interface->ifindex;

  if (bind (fd, (struct sockaddr *) (&s_addr),
	    sizeof (struct sockaddr_ll)) < 0)
    {
      zlog_warn ("open_packet_socket(): bind() failed: %s", safe_strerror (errno));
      return ISIS_WARNING;
    }

  circuit->fd = fd;

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      /*
       * Join to multicast groups
       * according to
       * 8.4.2 - Broadcast subnetwork IIH PDUs
       * FIXME: is there a case only one will fail??
       */
      if (circuit->circuit_is_type & IS_LEVEL_1)
	{
	  /* joining ALL_L1_ISS */
	  retval = isis_multicast_join (circuit->fd, 1,
					circuit->interface->ifindex);
	  /* joining ALL_ISS */
	  retval = isis_multicast_join (circuit->fd, 3,
					circuit->interface->ifindex);
	}
      if (circuit->circuit_is_type & IS_LEVEL_2)
	/* joining ALL_L2_ISS */
	retval = isis_multicast_join (circuit->fd, 2,
				      circuit->interface->ifindex);
    }
  else
    {
      retval =
	isis_multicast_join (circuit->fd, 0, circuit->interface->ifindex);
    }

  return retval;
}

#else

int
open_bpf_dev (struct isis_circuit *circuit)
{
  int i = 0, fd;
  char bpfdev[128];
  struct ifreq ifr;
  u_int16_t blen;
  int true = 1, false = 0;
  struct timeval timeout;
  struct bpf_program bpf_prog;

  do
    {
      (void) snprintf (bpfdev, sizeof (bpfdev), "/dev/bpf%d", i++);
      fd = open (bpfdev, O_RDWR);
    }
  while (fd < 0 && errno == EBUSY);

  if (fd < 0)
    {
      zlog_warn ("open_bpf_dev(): failed to create bpf socket: %s",
		 safe_strerror (errno));
      return ISIS_WARNING;
    }

  zlog_debug ("Opened BPF device %s", bpfdev);

  memcpy (ifr.ifr_name, circuit->interface->name, sizeof (ifr.ifr_name));
  if (ioctl (fd, BIOCSETIF, (caddr_t) & ifr) < 0)
    {
      zlog_warn ("open_bpf_dev(): failed to bind to interface: %s",
		 safe_strerror (errno));
      return ISIS_WARNING;
    }

  if (ioctl (fd, BIOCGBLEN, (caddr_t) & blen) < 0)
    {
      zlog_warn ("failed to get BPF buffer len");
      blen = circuit->interface->mtu;
    }

  readblen = blen;

  if (readbuff == NULL)
    readbuff = malloc (blen);

  zlog_debug ("BPF buffer len = %u", blen);

  /*  BPF(4): reads return immediately upon packet reception.
   *  Otherwise, a read will block until either the kernel
   *  buffer becomes full or a timeout occurs. 
   */
  if (ioctl (fd, BIOCIMMEDIATE, (caddr_t) & true) < 0)
    {
      zlog_warn ("failed to set BPF dev to immediate mode");
    }

#ifdef BIOCSSEESENT
  /*
   * We want to see only incoming packets
   */
  if (ioctl (fd, BIOCSSEESENT, (caddr_t) & false) < 0)
    {
      zlog_warn ("failed to set BPF dev to incoming only mode");
    }
#endif

  /*
   * ...but all of them
   */
  if (ioctl (fd, BIOCPROMISC, (caddr_t) & true) < 0)
    {
      zlog_warn ("failed to set BPF dev to promiscuous mode");
    }

  /*
   * If the buffer length is smaller than our mtu, lets try to increase it
   */
  if (blen < circuit->interface->mtu)
    {
      if (ioctl (fd, BIOCSBLEN, &circuit->interface->mtu) < 0)
	{
	  zlog_warn ("failed to set BPF buffer len (%u to %u)", blen,
		     circuit->interface->mtu);
	}
    }

  /*
   * Set a timeout parameter - hope this helps select()
   */
  timeout.tv_sec = 600;
  timeout.tv_usec = 0;
  if (ioctl (fd, BIOCSRTIMEOUT, (caddr_t) & timeout) < 0)
    {
      zlog_warn ("failed to set BPF device timeout");
    }

  /*
   * And set the filter
   */
  memset (&bpf_prog, 0, sizeof (struct bpf_program));
  bpf_prog.bf_len = 8;
  bpf_prog.bf_insns = &(llcfilter[0]);
  if (ioctl (fd, BIOCSETF, (caddr_t) & bpf_prog) < 0)
    {
      zlog_warn ("open_bpf_dev(): failed to install filter: %s",
		 safe_strerror (errno));
      return ISIS_WARNING;
    }

  assert (fd > 0);

  circuit->fd = fd;

  return ISIS_OK;
}

#endif /* GNU_LINUX */

/*
 * Create the socket and set the tx/rx funcs
 */
int
isis_sock_init (struct isis_circuit *circuit)
{
  int retval = ISIS_OK;

  if (isisd_privs.change (ZPRIVS_RAISE))
    zlog_err ("%s: could not raise privs, %s", __func__, safe_strerror (errno));

#ifdef GNU_LINUX
  retval = open_packet_socket (circuit);
#else
  retval = open_bpf_dev (circuit);
#endif

  if (retval != ISIS_OK)
    {
      zlog_warn ("%s: could not initialize the socket", __func__);
      goto end;
    }

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      circuit->tx = isis_send_pdu_bcast;
      circuit->rx = isis_recv_pdu_bcast;
    }
  else if (circuit->circ_type == CIRCUIT_T_P2P)
    {
      circuit->tx = isis_send_pdu_p2p;
      circuit->rx = isis_recv_pdu_p2p;
    }
  else
    {
      zlog_warn ("isis_sock_init(): unknown circuit type");
      retval = ISIS_WARNING;
      goto end;
    }

end:
  if (isisd_privs.change (ZPRIVS_LOWER))
    zlog_err ("%s: could not lower privs, %s", __func__, safe_strerror (errno));

  return retval;
}

static inline int
llc_check (u_char * llc)
{
  if (*llc != ISO_SAP || *(llc + 1) != ISO_SAP || *(llc + 2) != 3)
    return 0;

  return 1;
}

#ifdef GNU_LINUX
int
isis_recv_pdu_bcast (struct isis_circuit *circuit, u_char * ssnpa)
{
  int bytesread, addr_len;
  struct sockaddr_ll s_addr;
  u_char llc[LLC_LEN];

  addr_len = sizeof (s_addr);

  memset (&s_addr, 0, sizeof (struct sockaddr_ll));

  bytesread = recvfrom (circuit->fd, (void *) &llc,
			LLC_LEN, MSG_PEEK,
			(struct sockaddr *) &s_addr, (socklen_t *) &addr_len);

  if (bytesread < 0)
    {
      zlog_warn ("isis_recv_packet_bcast(): fd %d, recvfrom (): %s",
		 circuit->fd, safe_strerror (errno));
      zlog_warn ("circuit is %s", circuit->interface->name);
      zlog_warn ("circuit fd %d", circuit->fd);
      zlog_warn ("bytesread %d", bytesread);
      /* get rid of the packet */
      bytesread = read (circuit->fd, discard_buff, sizeof (discard_buff));
      return ISIS_WARNING;
    }
  /*
   * Filtering by llc field, discard packets sent by this host (other circuit)
   */
  if (!llc_check (llc) || s_addr.sll_pkttype == PACKET_OUTGOING)
    {
      /*  Read the packet into discard buff */
      bytesread = read (circuit->fd, discard_buff, sizeof (discard_buff));
      if (bytesread < 0)
	zlog_warn ("isis_recv_pdu_bcast(): read() failed");
      return ISIS_WARNING;
    }

  /* on lan we have to read to the static buff first */
  bytesread = recvfrom (circuit->fd, sock_buff, circuit->interface->mtu, 0,
			(struct sockaddr *) &s_addr, (socklen_t *) &addr_len);

  /* then we lose the LLC */
  memcpy (STREAM_DATA (circuit->rcv_stream),
	  sock_buff + LLC_LEN, bytesread - LLC_LEN);
  circuit->rcv_stream->putp = bytesread - LLC_LEN;
  circuit->rcv_stream->endp = bytesread - LLC_LEN;

  memcpy (ssnpa, &s_addr.sll_addr, s_addr.sll_halen);

  return ISIS_OK;
}

int
isis_recv_pdu_p2p (struct isis_circuit *circuit, u_char * ssnpa)
{
  int bytesread, addr_len;
  struct sockaddr_ll s_addr;

  memset (&s_addr, 0, sizeof (struct sockaddr_ll));
  addr_len = sizeof (s_addr);

  /* we can read directly to the stream */
  bytesread = recvfrom (circuit->fd, STREAM_DATA (circuit->rcv_stream),
			circuit->interface->mtu, 0,
			(struct sockaddr *) &s_addr, (socklen_t *) &addr_len);

  if (s_addr.sll_pkttype == PACKET_OUTGOING)
    {
      /*  Read the packet into discard buff */
      bytesread = read (circuit->fd, discard_buff, sizeof (discard_buff));
      if (bytesread < 0)
	zlog_warn ("isis_recv_pdu_p2p(): read() failed");
      return ISIS_WARNING;
    }

  circuit->rcv_stream->putp = bytesread;
  circuit->rcv_stream->endp = bytesread;

  /* If we don't have protocol type 0x00FE which is
   * ISO over GRE we exit with pain :)
   */
  if (ntohs (s_addr.sll_protocol) != 0x00FE)
    {
      zlog_warn ("isis_recv_pdu_p2p(): protocol mismatch(): %X",
		 ntohs (s_addr.sll_protocol));
      return ISIS_WARNING;
    }

  memcpy (ssnpa, &s_addr.sll_addr, s_addr.sll_halen);

  return ISIS_OK;
}

int
isis_send_pdu_bcast (struct isis_circuit *circuit, int level)
{
  /* we need to do the LLC in here because of P2P circuits, which will
   * not need it
   */
  int written = 1;
  struct sockaddr_ll sa;

  stream_set_getp (circuit->snd_stream, 0);
  memset (&sa, 0, sizeof (struct sockaddr_ll));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons (stream_get_endp (circuit->snd_stream) + LLC_LEN);
  sa.sll_ifindex = circuit->interface->ifindex;
  sa.sll_halen = ETH_ALEN;
  if (level == 1)
    memcpy (&sa.sll_addr, ALL_L1_ISS, ETH_ALEN);
  else
    memcpy (&sa.sll_addr, ALL_L2_ISS, ETH_ALEN);

  /* on a broadcast circuit */
  /* first we put the LLC in */
  sock_buff[0] = 0xFE;
  sock_buff[1] = 0xFE;
  sock_buff[2] = 0x03;

  /* then we copy the data */
  memcpy (sock_buff + LLC_LEN, circuit->snd_stream->data,
	  stream_get_endp (circuit->snd_stream));

  /* now we can send this */
  written = sendto (circuit->fd, sock_buff,
		    circuit->snd_stream->putp + LLC_LEN, 0,
		    (struct sockaddr *) &sa, sizeof (struct sockaddr_ll));

  return ISIS_OK;
}

int
isis_send_pdu_p2p (struct isis_circuit *circuit, int level)
{

  int written = 1;
  struct sockaddr_ll sa;

  stream_set_getp (circuit->snd_stream, 0);
  memset (&sa, 0, sizeof (struct sockaddr_ll));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons (stream_get_endp (circuit->snd_stream) + LLC_LEN);
  sa.sll_ifindex = circuit->interface->ifindex;
  sa.sll_halen = ETH_ALEN;
  if (level == 1)
    memcpy (&sa.sll_addr, ALL_L1_ISS, ETH_ALEN);
  else
    memcpy (&sa.sll_addr, ALL_L2_ISS, ETH_ALEN);


  /* lets try correcting the protocol */
  sa.sll_protocol = htons (0x00FE);
  written = sendto (circuit->fd, circuit->snd_stream->data,
		    circuit->snd_stream->putp, 0, (struct sockaddr *) &sa,
		    sizeof (struct sockaddr_ll));

  return ISIS_OK;
}

#else

int
isis_recv_pdu_bcast (struct isis_circuit *circuit, u_char * ssnpa)
{
  int bytesread = 0, bytestoread, offset, one = 1;
  struct bpf_hdr *bpf_hdr;

  assert (circuit->fd > 0);

  if (ioctl (circuit->fd, FIONREAD, (caddr_t) & bytestoread) < 0)
    {
      zlog_warn ("ioctl() FIONREAD failed: %s", safe_strerror (errno));
    }

  if (bytestoread)
    {
      bytesread = read (circuit->fd, readbuff, readblen);
    }
  if (bytesread < 0)
    {
      zlog_warn ("isis_recv_pdu_bcast(): read() failed: %s",
		 safe_strerror (errno));
      return ISIS_WARNING;
    }

  if (bytesread == 0)
    return ISIS_WARNING;

  bpf_hdr = (struct bpf_hdr *) readbuff;

  assert (bpf_hdr->bh_caplen == bpf_hdr->bh_datalen);

  offset = bpf_hdr->bh_hdrlen + LLC_LEN + ETHER_HDR_LEN;

  /* then we lose the BPF, LLC and ethernet headers */
  memcpy (STREAM_DATA (circuit->rcv_stream),
	  readbuff + offset, bpf_hdr->bh_caplen - LLC_LEN - ETHER_HDR_LEN);

  circuit->rcv_stream->putp = bpf_hdr->bh_caplen - LLC_LEN - ETHER_HDR_LEN;
  circuit->rcv_stream->endp = bpf_hdr->bh_caplen - LLC_LEN - ETHER_HDR_LEN;
  circuit->rcv_stream->getp = 0;

  memcpy (ssnpa, readbuff + bpf_hdr->bh_hdrlen + ETHER_ADDR_LEN,
	  ETHER_ADDR_LEN);

  if (ioctl (circuit->fd, BIOCFLUSH, &one) < 0)
    zlog_warn ("Flushing failed: %s", safe_strerror (errno));

  return ISIS_OK;
}

int
isis_recv_pdu_p2p (struct isis_circuit *circuit, u_char * ssnpa)
{
  int bytesread;

  bytesread = read (circuit->fd, STREAM_DATA (circuit->rcv_stream),
		    circuit->interface->mtu);

  if (bytesread < 0)
    {
      zlog_warn ("isis_recv_pdu_p2p(): read () failed: %s", safe_strerror (errno));
      return ISIS_WARNING;
    }

  circuit->rcv_stream->putp = bytesread;
  circuit->rcv_stream->endp = bytesread;

  return ISIS_OK;
}

int
isis_send_pdu_bcast (struct isis_circuit *circuit, int level)
{
  struct ether_header *eth;
  int written;

  stream_set_getp (circuit->snd_stream, 0);

  /*
   * First the eth header
   */
  eth = (struct ether_header *) sock_buff;
  if (level == 1)
    memcpy (eth->ether_dhost, ALL_L1_ISS, ETHER_ADDR_LEN);
  else
    memcpy (eth->ether_dhost, ALL_L2_ISS, ETHER_ADDR_LEN);
  memcpy (eth->ether_shost, circuit->u.bc.snpa, ETHER_ADDR_LEN);
  eth->ether_type = htons (stream_get_endp (circuit->snd_stream) + LLC_LEN);

  /*
   * Then the LLC
   */
  sock_buff[ETHER_HDR_LEN] = ISO_SAP;
  sock_buff[ETHER_HDR_LEN + 1] = ISO_SAP;
  sock_buff[ETHER_HDR_LEN + 2] = 0x03;

  /* then we copy the data */
  memcpy (sock_buff + (LLC_LEN + ETHER_HDR_LEN), circuit->snd_stream->data,
	  stream_get_endp (circuit->snd_stream));

  /* now we can send this */
  written = write (circuit->fd, sock_buff,
		   circuit->snd_stream->putp + LLC_LEN + ETHER_HDR_LEN);

  return ISIS_OK;
}

int
isis_send_pdu_p2p (struct isis_circuit *circuit, int level)
{
  return ISIS_OK;
}

#endif /* GNU_LINUX */
