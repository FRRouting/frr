// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - BFD support
 * Copyright (C) 2018 Christian Franke
 */
#ifndef ISIS_BFD_H
#define ISIS_BFD_H

/* RFC6213 MTID/NLPID supported pair */
#define ISIS_BFD_MT_STANDARD_NLP_IPV4	  0x1
#define ISIS_BFD_MT_STANDARD_NLP_IPV6	  0x2
#define ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6 0x4

struct isis_circuit;
struct event_loop;

void isis_bfd_circuit_cmd(struct isis_circuit *circuit);
void isis_bfd_circuit_update_rfc6213(struct isis_circuit *circuit);

void isis_bfd_init(struct event_loop *tm);

#endif

