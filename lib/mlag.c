/* mlag generic code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>

#include <mlag.h>

char *mlag_role2str(enum mlag_role role, char *buf, size_t size)
{
	switch (role) {
	case MLAG_ROLE_NONE:
		snprintf(buf, size, "NONE");
		break;
	case MLAG_ROLE_PRIMARY:
		snprintf(buf, size, "PRIMARY");
		break;
	case MLAG_ROLE_SECONDARY:
		snprintf(buf, size, "SECONDARY");
		break;
	}

	return buf;
}
