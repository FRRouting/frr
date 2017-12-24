/*
 * IS-IS Rout(e)ing protocol - isis_bpf.c
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#if ISIS_METHOD == ISIS_METHOD_BPF
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>

#include "log.h"
#include "network.h"
#include "stream.h"
#include "if.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isisd.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_network.h"

#include "privs.h"

struct bpf_insn llcfilter[] = {
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
		 ETHER_HDR_LEN), /* check first byte */
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ISO_SAP, 0, 5),
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + 1),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ISO_SAP, 0,
		 3), /* check second byte */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETHER_HDR_LEN + 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x03, 0, 1), /* check third byte */
	BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
	BPF_STMT(BPF_RET + BPF_K, 0)};
u_int readblen = 0;
u_char *readbuff = NULL;

/*
 * Table 9 - Architectural constants for use with ISO 8802 subnetworks
 * ISO 10589 - 8.4.8
 */

u_char ALL_L1_ISS[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x14};
u_char ALL_L2_ISS[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x15};
u_char ALL_ISS[6] = {0x09, 0x00, 0x2B, 0x00, 0x00, 0x05};
u_char ALL_ESS[6] = {0x09, 0x00, 0x2B, 0x00, 0x00, 0x04};

static char sock_buff[8192];

static int open_bpf_dev(struct isis_circuit *circuit)
{
	int i = 0, fd;
	char bpfdev[128];
	struct ifreq ifr;
	u_int blen, immediate;
#ifdef BIOCSSEESENT
	u_int seesent;
#endif
	struct timeval timeout;
	struct bpf_program bpf_prog;

	do {
		(void)snprintf(bpfdev, sizeof(bpfdev), "/dev/bpf%d", i++);
		fd = open(bpfdev, O_RDWR);
	} while (fd < 0 && errno == EBUSY);

	if (fd < 0) {
		zlog_warn("open_bpf_dev(): failed to create bpf socket: %s",
			  safe_strerror(errno));
		return ISIS_WARNING;
	}

	zlog_debug("Opened BPF device %s", bpfdev);

	memcpy(ifr.ifr_name, circuit->interface->name, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) < 0) {
		zlog_warn("open_bpf_dev(): failed to bind to interface: %s",
			  safe_strerror(errno));
		return ISIS_WARNING;
	}

	if (ioctl(fd, BIOCGBLEN, (caddr_t)&blen) < 0) {
		zlog_warn("failed to get BPF buffer len");
		blen = circuit->interface->mtu;
	}

	readblen = blen;

	if (readbuff == NULL)
		readbuff = malloc(blen);

	zlog_debug("BPF buffer len = %u", blen);

	/*  BPF(4): reads return immediately upon packet reception.
	 *  Otherwise, a read will block until either the kernel
	 *  buffer becomes full or a timeout occurs.
	 */
	immediate = 1;
	if (ioctl(fd, BIOCIMMEDIATE, (caddr_t)&immediate) < 0) {
		zlog_warn("failed to set BPF dev to immediate mode");
	}

#ifdef BIOCSSEESENT
	/*
	 * We want to see only incoming packets
	 */
	seesent = 0;
	if (ioctl(fd, BIOCSSEESENT, (caddr_t)&seesent) < 0) {
		zlog_warn("failed to set BPF dev to incoming only mode");
	}
#endif

	/*
	 * ...but all of them
	 */
	if (ioctl(fd, BIOCPROMISC) < 0) {
		zlog_warn("failed to set BPF dev to promiscuous mode");
	}

	/*
	 * If the buffer length is smaller than our mtu, lets try to increase it
	 */
	if (blen < circuit->interface->mtu) {
		if (ioctl(fd, BIOCSBLEN, &circuit->interface->mtu) < 0) {
			zlog_warn("failed to set BPF buffer len (%u to %u)",
				  blen, circuit->interface->mtu);
		}
	}

	/*
	 * Set a timeout parameter - hope this helps select()
	 */
	timeout.tv_sec = 600;
	timeout.tv_usec = 0;
	if (ioctl(fd, BIOCSRTIMEOUT, (caddr_t)&timeout) < 0) {
		zlog_warn("failed to set BPF device timeout");
	}

	/*
	 * And set the filter
	 */
	memset(&bpf_prog, 0, sizeof(struct bpf_program));
	bpf_prog.bf_len = 8;
	bpf_prog.bf_insns = &(llcfilter[0]);
	if (ioctl(fd, BIOCSETF, (caddr_t)&bpf_prog) < 0) {
		zlog_warn("open_bpf_dev(): failed to install filter: %s",
			  safe_strerror(errno));
		return ISIS_WARNING;
	}

	assert(fd > 0);

	circuit->fd = fd;

	return ISIS_OK;
}

/*
 * Create the socket and set the tx/rx funcs
 */
int isis_sock_init(struct isis_circuit *circuit)
{
	int retval = ISIS_OK;

	if (isisd_privs.change(ZPRIVS_RAISE))
		zlog_err("%s: could not raise privs, %s", __func__,
			 safe_strerror(errno));

	retval = open_bpf_dev(circuit);

	if (retval != ISIS_OK) {
		zlog_warn("%s: could not initialize the socket", __func__);
		goto end;
	}

	if (if_is_broadcast(circuit->interface)) {
		circuit->tx = isis_send_pdu_bcast;
		circuit->rx = isis_recv_pdu_bcast;
	} else {
		zlog_warn("isis_sock_init(): unknown circuit type");
		retval = ISIS_WARNING;
		goto end;
	}

end:
	if (isisd_privs.change(ZPRIVS_LOWER))
		zlog_err("%s: could not lower privs, %s", __func__,
			 safe_strerror(errno));

	return retval;
}

int isis_recv_pdu_bcast(struct isis_circuit *circuit, u_char *ssnpa)
{
	int bytesread = 0, bytestoread, offset, one = 1;
	struct bpf_hdr *bpf_hdr;

	assert(circuit->fd > 0);

	if (ioctl(circuit->fd, FIONREAD, (caddr_t)&bytestoread) < 0) {
		zlog_warn("ioctl() FIONREAD failed: %s", safe_strerror(errno));
	}

	if (bytestoread) {
		bytesread = read(circuit->fd, readbuff, readblen);
	}
	if (bytesread < 0) {
		zlog_warn("isis_recv_pdu_bcast(): read() failed: %s",
			  safe_strerror(errno));
		return ISIS_WARNING;
	}

	if (bytesread == 0)
		return ISIS_WARNING;

	bpf_hdr = (struct bpf_hdr *)readbuff;

	assert(bpf_hdr->bh_caplen == bpf_hdr->bh_datalen);

	offset = bpf_hdr->bh_hdrlen + LLC_LEN + ETHER_HDR_LEN;

	/* then we lose the BPF, LLC and ethernet headers */
	stream_write(circuit->rcv_stream, readbuff + offset,
		     bpf_hdr->bh_caplen - LLC_LEN - ETHER_HDR_LEN);
	stream_set_getp(circuit->rcv_stream, 0);

	memcpy(ssnpa, readbuff + bpf_hdr->bh_hdrlen + ETH_ALEN,
	       ETH_ALEN);

	if (ioctl(circuit->fd, BIOCFLUSH, &one) < 0)
		zlog_warn("Flushing failed: %s", safe_strerror(errno));

	return ISIS_OK;
}

int isis_send_pdu_bcast(struct isis_circuit *circuit, int level)
{
	struct ether_header *eth;
	ssize_t written;
	size_t buflen;

	buflen = stream_get_endp(circuit->snd_stream) + LLC_LEN + ETHER_HDR_LEN;
	if (buflen > sizeof(sock_buff)) {
		zlog_warn(
			"isis_send_pdu_bcast: sock_buff size %zu is less than "
			"output pdu size %zu on circuit %s",
			sizeof(sock_buff), buflen, circuit->interface->name);
		return ISIS_WARNING;
	}

	stream_set_getp(circuit->snd_stream, 0);

	/*
	 * First the eth header
	 */
	eth = (struct ether_header *)sock_buff;
	if (level == 1)
		memcpy(eth->ether_dhost, ALL_L1_ISS, ETH_ALEN);
	else
		memcpy(eth->ether_dhost, ALL_L2_ISS, ETH_ALEN);
	memcpy(eth->ether_shost, circuit->u.bc.snpa, ETH_ALEN);
	size_t frame_size = stream_get_endp(circuit->snd_stream) + LLC_LEN;
	eth->ether_type = htons(isis_ethertype(frame_size));

	/*
	 * Then the LLC
	 */
	sock_buff[ETHER_HDR_LEN] = ISO_SAP;
	sock_buff[ETHER_HDR_LEN + 1] = ISO_SAP;
	sock_buff[ETHER_HDR_LEN + 2] = 0x03;

	/* then we copy the data */
	memcpy(sock_buff + (LLC_LEN + ETHER_HDR_LEN), circuit->snd_stream->data,
	       stream_get_endp(circuit->snd_stream));

	/* now we can send this */
	written = write(circuit->fd, sock_buff, buflen);
	if (written < 0) {
		zlog_warn("IS-IS bpf: could not transmit packet on %s: %s",
			  circuit->interface->name, safe_strerror(errno));
		if (ERRNO_IO_RETRY(errno))
			return ISIS_WARNING;
		return ISIS_ERROR;
	}

	return ISIS_OK;
}

#endif /* ISIS_METHOD == ISIS_METHOD_BPF */
