// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_flags.h
 *                             Routines for manipulation of SSN and SRM flags
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#ifndef _ZEBRA_ISIS_FLAGS_H
#define _ZEBRA_ISIS_FLAGS_H

/* The grand plan is to support 1024 circuits so we have 32*32 bit flags
 * the support will be achived using the newest drafts */
#define ISIS_MAX_CIRCUITS 32 /* = 1024 */

/*
 * Flags structure for SSN and SRM flags
 */
struct flags {
	int maxindex;
	struct list *free_idcs;
};

void flags_initialize(struct flags *flags);
long int flags_get_index(struct flags *flags);
void flags_free_index(struct flags *flags, long int index);
int flags_any_set(uint32_t *flags);

#define _ISIS_SET_FLAG(F, C)                                                   \
	{                                                                      \
		F[(C) >> 5] |= (1 << ((C)&0x1F));                              \
	}
#define ISIS_SET_FLAG(F, C) _ISIS_SET_FLAG(F, C->idx)

#define _ISIS_CLEAR_FLAG(F, C)                                                 \
	{                                                                      \
		F[(C) >> 5] &= ~(1 << ((C)&0x1F));                             \
	}
#define ISIS_CLEAR_FLAG(F, C) _ISIS_CLEAR_FLAG(F, C->idx)

#define _ISIS_CHECK_FLAG(F, C)  (F[(C)>>5] & (1<<((C) & 0x1F)))
#define ISIS_CHECK_FLAG(F, C) _ISIS_CHECK_FLAG(F, C->idx)

/* sets all u_32int_t flags to 1 */
#define ISIS_FLAGS_SET_ALL(FLAGS)                                              \
	{                                                                      \
		memset(FLAGS, 0xFF, ISIS_MAX_CIRCUITS * 4);                    \
	}

#define ISIS_FLAGS_CLEAR_ALL(FLAGS)                                            \
	{                                                                      \
		memset(FLAGS, 0x00, ISIS_MAX_CIRCUITS * 4);                    \
	}

#endif /* _ZEBRA_ISIS_FLAGS_H */
