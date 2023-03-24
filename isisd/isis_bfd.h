// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - BFD support
 * Copyright (C) 2018 Christian Franke
 */
#ifndef ISIS_BFD_H
#define ISIS_BFD_H

struct isis_circuit;
struct event_loop;

void isis_bfd_circuit_cmd(struct isis_circuit *circuit);
void isis_bfd_init(struct event_loop *tm);

#endif

