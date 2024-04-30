// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_network.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */


#ifndef _ZEBRA_ISIS_NETWORK_H
#define _ZEBRA_ISIS_NETWORK_H

extern uint8_t ALL_L1_ISYSTEMS[];
extern uint8_t ALL_L2_ISYSTEMS[];

int isis_sock_init(struct isis_circuit *circuit);

int isis_recv_pdu_bcast(struct isis_circuit *circuit, uint8_t *ssnpa);
int isis_recv_pdu_p2p(struct isis_circuit *circuit, uint8_t *ssnpa);
int isis_send_pdu_bcast(struct isis_circuit *circuit, int level);
int isis_send_pdu_p2p(struct isis_circuit *circuit, int level);

#endif /* _ZEBRA_ISIS_NETWORK_H */
