/*
 * Memory and dynamic module VTY routine
 *
 * Copyright (C) 1998 Kunihiro Ishiguro
 * Copyright (C) 2016-2017  David Lamparter for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
/* malloc.h is generally obsolete, however GNU Libc mallinfo wants it. */
#if (defined(GNU_LINUX) && defined(HAVE_MALLINFO))
#include <malloc.h>
#endif /* HAVE_MALLINFO */
#include <dlfcn.h>
#include <link.h>

#include "log.h"
#include "memory.h"
#include "module.h"
#include "memory_vty.h"

/* Looking up memory status from vty interface. */
#include "vector.h"
#include "vty.h"
#include "command.h"

#ifdef HAVE_MALLINFO
static int show_memory_mallinfo(struct vty *vty)
{
	struct mallinfo minfo = mallinfo();
	char buf[MTYPE_MEMSTR_LEN];

	vty_out(vty, "System allocator statistics:\n");
	vty_out(vty, "  Total heap allocated:  %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.arena));
	vty_out(vty, "  Holding block headers: %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.hblkhd));
	vty_out(vty, "  Used small blocks:     %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.usmblks));
	vty_out(vty, "  Used ordinary blocks:  %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.uordblks));
	vty_out(vty, "  Free small blocks:     %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.fsmblks));
	vty_out(vty, "  Free ordinary blocks:  %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.fordblks));
	vty_out(vty, "  Ordinary blocks:       %ld\n",
		(unsigned long)minfo.ordblks);
	vty_out(vty, "  Small blocks:          %ld\n",
		(unsigned long)minfo.smblks);
	vty_out(vty, "  Holding blocks:        %ld\n",
		(unsigned long)minfo.hblks);
	vty_out(vty, "(see system documentation for 'mallinfo' for meaning)\n");
	return 1;
}
#endif /* HAVE_MALLINFO */

static int qmem_walker(void *arg, struct memgroup *mg, struct memtype *mt)
{
	struct vty *vty = arg;
	if (!mt)
		vty_out(vty, "--- qmem %s ---\n", mg->name);
	else {
		if (mt->n_alloc != 0) {
			char size[32];
			snprintf(size, sizeof(size), "%6zu", mt->size);
			vty_out(vty, "%-30s: %10zu  %s\n", mt->name,
				mt->n_alloc,
				mt->size == 0 ? ""
					      : mt->size == SIZE_VAR
							? "(variably sized)"
							: size);
		}
	}
	return 0;
}


DEFUN (show_memory,
       show_memory_cmd,
       "show memory",
       "Show running system information\n"
       "Memory statistics\n")
{
#ifdef HAVE_MALLINFO
	show_memory_mallinfo(vty);
#endif /* HAVE_MALLINFO */

	qmem_walk(qmem_walker, vty);
	return CMD_SUCCESS;
}

DEFUN (show_modules,
       show_modules_cmd,
       "show modules",
       "Show running system information\n"
       "Loaded modules\n")
{
	struct frrmod_runtime *plug = frrmod_list;

	vty_out(vty, "%-12s %-25s %s\n\n", "Module Name", "Version",
		"Description");
	while (plug) {
		const struct frrmod_info *i = plug->info;

		vty_out(vty, "%-12s %-25s %s\n", i->name, i->version,
			i->description);
		if (plug->dl_handle) {
#ifdef HAVE_DLINFO_ORIGIN
			char origin[MAXPATHLEN] = "";
			dlinfo(plug->dl_handle, RTLD_DI_ORIGIN, &origin);
#ifdef HAVE_DLINFO_LINKMAP
			const char *name;
			struct link_map *lm = NULL;
			dlinfo(plug->dl_handle, RTLD_DI_LINKMAP, &lm);
			if (lm) {
				name = strrchr(lm->l_name, '/');
				name = name ? name + 1 : lm->l_name;
				vty_out(vty, "\tfrom: %s/%s\n", origin, name);
			}
#else
			vty_out(vty, "\tfrom: %s \n", origin, plug->load_name);
#endif
#else
			vty_out(vty, "\tfrom: %s\n", plug->load_name);
#endif
		}
		plug = plug->next;
	}
	return CMD_SUCCESS;
}

void memory_init(void)
{
	install_element(VIEW_NODE, &show_memory_cmd);
	install_element(VIEW_NODE, &show_modules_cmd);
}

/* Stats querying from users */
/* Return a pointer to a human friendly string describing
 * the byte count passed in. E.g:
 * "0 bytes", "2048 bytes", "110kB", "500MiB", "11GiB", etc.
 * Up to 4 significant figures will be given.
 * The pointer returned may be NULL (indicating an error)
 * or point to the given buffer, or point to static storage.
 */
const char *mtype_memstr(char *buf, size_t len, unsigned long bytes)
{
	unsigned int m, k;

	/* easy cases */
	if (!bytes)
		return "0 bytes";
	if (bytes == 1)
		return "1 byte";

	/*
	 * When we pass the 2gb barrier mallinfo() can no longer report
	 * correct data so it just does something odd...
	 * Reporting like Terrabytes of data.  Which makes users...
	 * edgy.. yes edgy that's the term for it.
	 * So let's just give up gracefully
	 */
	if (bytes > 0x7fffffff)
		return "> 2GB";

	m = bytes >> 20;
	k = bytes >> 10;

	if (m > 10) {
		if (bytes & (1 << 19))
			m++;
		snprintf(buf, len, "%d MiB", m);
	} else if (k > 10) {
		if (bytes & (1 << 9))
			k++;
		snprintf(buf, len, "%d KiB", k);
	} else
		snprintf(buf, len, "%ld bytes", bytes);

	return buf;
}
