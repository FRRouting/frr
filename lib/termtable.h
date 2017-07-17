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
#ifndef _TERMTABLE_H_
#define _TERMTABLE_H_

#include <zebra.h>

enum ttable_align {
	LEFT,
	RIGHT,
	TOP,
	BOTTOM,
};

struct ttable_border {
	char top;
	char bottom;
	char left;
	char right;

	bool top_on;
	bool bottom_on;
	bool left_on;
	bool right_on;
};

/* cell style and cell */
struct ttable_cellstyle {
	short lpad;
	short rpad;
	enum ttable_align align;
	struct ttable_border border;
};

struct ttable_cell {
	char *text;
	struct ttable_cellstyle style;
};

/* table style and table */
struct ttable_style {
	char corner;     /* intersection */
	int indent;      /* left table indent */
	bool rownums_on; /* show row numbers; unimplemented */

	struct ttable_border border;
	struct ttable_cellstyle cell;
};

struct ttable {
	int nrows;		    /* number of rows */
	int ncols;		    /* number of cols */
	struct ttable_cell **table; /* table, row x col */
	size_t size;		    /* size */
	struct ttable_style style;  /* style */
};

/* some predefined styles */
#define TTSTYLE_ASCII 0
#define TTSTYLE_BLANK 1

extern struct ttable_style ttable_styles[2];

/**
 * Creates a new table with the default style, which looks like this:
 *
 * +----------+----------+
 * | column 1 | column 2 |
 * +----------+----------+
 * | data...  | data!!   |
 * +----------+----------+
 * | datums   | 12345    |
 * +----------+----------+
 *
 * @return the created table
 */
struct ttable *ttable_new(struct ttable_style *tts);

/**
 * Deletes a table and releases all associated resources.
 *
 * @param tt the table to destroy
 */
void ttable_del(struct ttable *tt);

/**
 * Deletes an individual cell.
 *
 * @param cell the cell to destroy
 */
void ttable_cell_del(struct ttable_cell *cell);

/**
 * Inserts a new row at the given index.
 *
 * The row contents are determined by a format string. The format string has
 * the same form as a regular printf format string, except that columns are
 * delimited by '|'. For example, to make the first column of the table above,
 * the call is:
 *
 *   ttable_insert_row(<tt>, <n>, "%s|%s", "column 1", "column 2");
 *
 * All features of printf format strings are permissible here.
 *
 * Caveats:
 *  - At present you cannot insert '|' into a cell's contents.
 *  - If there are N columns, '|' must appear n-1 times or the row will not be
 *    created
 *
 * @param tt table to insert row into
 * @param row the row number (begins at 0)
 * @param format column-separated format string
 * @param ... arguments to format string
 *
 * @return pointer to the first cell in the created row, or NULL if not enough
 * columns were specified
 */
struct ttable_cell *ttable_insert_row(struct ttable *tt, unsigned int row,
				      const char *format, ...)
	PRINTF_ATTRIBUTE(3, 4);
/**
 * Inserts a new row at the end of the table.
 *
 * The row contents are determined by a format string. The format string has
 * the same form as a regular printf format string, except that columns are
 * delimited by '|'. For example, to make the first column of the table above,
 * the call is:
 *
 *   ttable_add_row(<tt>, "%s|%s", "column 1", "column 2");
 *
 * All features of printf format strings are permissible here.
 *
 * Caveats:
 *  - At present you cannot insert '|' into a cell's contents.
 *  - If there are N columns, '|' must appear n-1 times or the row will not be
 *    created
 *
 * @param tt table to insert row into
 * @param format column-separated format string
 * @param ... arguments to format string
 *
 * @return pointer to the first cell in the created row, or NULL if not enough
 * columns were specified
 */
struct ttable_cell *ttable_add_row(struct ttable *tt, const char *format, ...)
	PRINTF_ATTRIBUTE(2, 3);

/**
 * Removes a row from the table.
 *
 * @param tt table to delete row from
 * @param row the row number (begins at 0)
 */
void ttable_del_row(struct ttable *tt, unsigned int row);

/**
 * Sets alignment for a range of cells.
 *
 * Available alignments are LEFT and RIGHT. Cell contents will be aligned
 * accordingly, while respecting padding (if any). Suppose a cell has:
 *
 * lpad = 1
 * rpad = 1
 * align = RIGHT
 * text = 'datums'
 *
 * The cell would look like:
 *
 *  +-------------------+
 *  |            datums |
 *  +-------------------+
 *
 * On the other hand:
 *
 * lpad = 1
 * rpad = 10
 * align = RIGHT
 * text = 'datums'
 *
 *  +-------------------+
 *  |   datums          |
 *  +-------------------+
 *
 * The default alignment is LEFT.
 *
 * @param tt the table to set alignment on
 * @param srow starting row index
 * @param scol starting column index
 * @param nrow # rows to align
 * @param ncol # cols to align
 * @param align the alignment to set
 */
void ttable_align(struct ttable *tt, unsigned int srow, unsigned int scol,
		  unsigned int erow, unsigned int ecol,
		  enum ttable_align align);

/**
 * Sets padding for a range of cells.
 *
 * Available padding options are LEFT and RIGHT (the alignment enum is reused).
 * Both options may be set. Padding is treated as though it is stuck to the
 * walls of the cell. Suppose a cell has:
 *
 * lpad = 4
 * rpad = 2
 * align = RIGHT
 * text = 'datums'
 *
 * The cell padding, marked by '.', would look like:
 *
 *  +--------------+
 *  |    .datums.  |
 *  +--------------+
 *
 * If the column is wider than the cell, the cell contents are aligned in an
 * additional padded field according to the cell alignment.
 *
 *  +--------------------+
 *  | Data!!!11!~~~~~:-) |
 *  +--------------------+
 *  |    .      datums.  |
 *  +--------------------+
 *
 * @param tt the table to set padding on
 * @param srow starting row index
 * @param scol starting column index
 * @param nrow # rows to pad
 * @param ncol # cols to pad
 * @param align LEFT or RIGHT
 * @param pad # spaces to pad with
 */
void ttable_pad(struct ttable *tt, unsigned int srow, unsigned int scol,
		unsigned int nrow, unsigned int ncol, enum ttable_align align,
		short pad);

/**
 * Restyle all cells according to table.cell.style.
 *
 * @param tt table to restyle
 */
void ttable_restyle(struct ttable *tt);

/**
 * Turn left/right column separators on or off for specified column.
 *
 * @param tt table
 * @param col column index
 * @param align left or right separators
 * @param on true/false for on/off
 * @param sep character to use
 */
void ttable_colseps(struct ttable *tt, unsigned int col,
		    enum ttable_align align, bool on, char sep);

/**
 * Turn bottom row separators on or off for specified row.
 *
 * @param tt table
 * @param row row index
 * @param align left or right separators
 * @param on true/false for on/off
 * @param sep character to use
 */
void ttable_rowseps(struct ttable *tt, unsigned int row,
		    enum ttable_align align, bool on, char sep);

/**
 * Dumps a table to a heap-allocated string.
 *
 * Caller must free this string after use with
 *
 *   XFREE (MTYPE_TMP, str);
 *
 * @param tt the table to dump
 * @param newline the desired newline sequence to use, null terminated.
 * @return table in text form
 */
char *ttable_dump(struct ttable *tt, const char *newline);

#endif /* _TERMTABLE_H */
