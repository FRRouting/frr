// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - BFD support
 * Copyright (C) 2018 Christian Franke
 */
#ifndef ISIS_BFD_H
#define ISIS_BFD_H

struct isis_circuit;
struct thread_master;

void isis_bfd_circuit_cmd(struct isis_circuit *circuit);
void isis_bfd_init(struct thread_master *tm);

#endif

