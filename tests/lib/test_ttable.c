/*
 * ASCII table generator.
 * Copyright (C) 2017  Cumulus Networks
 * Quentin Young
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
#include <termtable.h>
#include <memory.h>

int main(int argc, char **argv)
{
	char *table;

	struct ttable *tt = ttable_new(&ttable_styles[TTSTYLE_ASCII]);

	/* test printf compatibility and dimension counters */
	ttable_add_row(tt, "%s|%s|%s", "Column 1", "Column 2", "Column 3");
	assert(tt->ncols == 3);
	assert(tt->nrows == 1);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* add new row with 1 column, assert that it is not added */
	assert(ttable_add_row(tt, "%s", "Garbage") == NULL);
	assert(tt->ncols == 3);
	assert(tt->nrows == 1);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* add new row, assert that it is added */
	assert(ttable_add_row(tt, "%s|%s|%s", "a", "b", "c"));
	assert(tt->ncols == 3);
	assert(tt->nrows == 2);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* add empty row, assert that it is added */
	assert(ttable_add_row(tt, "||"));
	assert(tt->ncols == 3);
	assert(tt->nrows == 3);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* delete 1st row, assert that it is removed */
	ttable_del_row(tt, 0);
	assert(tt->ncols == 3);
	assert(tt->nrows == 2);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* delete last row, assert that it is removed */
	ttable_del_row(tt, 0);
	assert(tt->ncols == 3);
	assert(tt->nrows == 1);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* delete the remaining row, check dumping an empty table */
	ttable_del_row(tt, 0);
	assert(tt->ncols == 0);
	assert(tt->nrows == 0);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* add new row */
	ttable_add_row(tt, "%s|%s||%s|%9d", "slick", "black", "triple", 1337);
	assert(tt->ncols == 5);
	assert(tt->nrows == 1);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* add bigger row */
	ttable_add_row(tt, "%s|%s||%s|%s",
		       "nebula dusk session streets twilight "
		       "pioneer beats yeah",
		       "prarie dog", "cornmeal", ":O -*_-*");
	assert(tt->ncols == 5);
	assert(tt->nrows == 2);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* insert new row at beginning */
	ttable_insert_row(tt, 0, "%s|%s||%d|%lf", "converting", "vegetarians",
			  2, 2015.0);
	assert(tt->ncols == 5);
	assert(tt->nrows == 3);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* insert new row at end */
	ttable_insert_row(tt, tt->nrows - 1, "%s|%s||%d|%ld", "converting",
			  "vegetarians", 1, 2003L);
	assert(tt->ncols == 5);
	assert(tt->nrows == 4);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* insert new row at middle */
	ttable_insert_row(tt, 1, "%s|%s||%s|%ld", "she", "pioneer", "aki", 1l);
	assert(tt->ncols == 5);
	assert(tt->nrows == 5);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* set alignment */
	ttable_align(tt, 0, 1, 2, 2, LEFT);
	assert(tt->ncols == 5);
	assert(tt->nrows == 5);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	ttable_align(tt, 0, 1, 5, 1, RIGHT);
	assert(tt->ncols == 5);
	assert(tt->nrows == 5);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* set padding */
	ttable_pad(tt, 0, 1, 1, 1, RIGHT, 2);
	assert(tt->ncols == 5);
	assert(tt->nrows == 5);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	ttable_pad(tt, 0, 0, 5, 4, LEFT, 2);
	assert(tt->ncols == 5);
	assert(tt->nrows == 5);
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* restyle */
	tt->style.cell.border.bottom_on = false;
	tt->style.cell.border.top_on = false;
	tt->style.cell.border.right_on = false;
	tt->style.cell.border.left_on = false;
	ttable_restyle(tt);

	/* top & double bottom border for top row */
	ttable_rowseps(tt, 0, BOTTOM, true, '-');
	ttable_rowseps(tt, 1, TOP, true, '-');
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* column separators for leftmost column */
	ttable_colseps(tt, 0, RIGHT, true, '|');
	table = ttable_dump(tt, "\n");
	fprintf(stdout, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	/* delete table */
	ttable_del(tt);
}
