// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_flags.c
 *                             Routines for manipulation of SSN and SRM flags
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#include <zebra.h>
#include "log.h"
#include "linklist.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"

void flags_initialize(struct flags *flags)
{
	flags->maxindex = 0;
	flags->free_idcs = NULL;
}

long int flags_get_index(struct flags *flags)
{
	struct listnode *node;
	long int index;

	if (flags->free_idcs == NULL || flags->free_idcs->count == 0) {
		index = flags->maxindex++;
	} else {
		node = listhead(flags->free_idcs);
		index = (long int)listgetdata(node);
		listnode_delete(flags->free_idcs, (void *)index);
		index--;
	}

	return index;
}

void flags_free_index(struct flags *flags, long int index)
{
	if (index + 1 == flags->maxindex) {
		flags->maxindex--;
		return;
	}

	if (flags->free_idcs == NULL) {
		flags->free_idcs = list_new();
	}

	listnode_add(flags->free_idcs, (void *)(index + 1));

	return;
}

int flags_any_set(uint32_t *flags)
{
	uint32_t zero[ISIS_MAX_CIRCUITS];
	memset(zero, 0x00, ISIS_MAX_CIRCUITS * 4);

	return bcmp(flags, zero, ISIS_MAX_CIRCUITS * 4);
}
