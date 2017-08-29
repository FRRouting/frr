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
#include <stdio.h>

#include "memory.h"
#include "termtable.h"

DEFINE_MTYPE_STATIC(LIB, TTABLE, "ASCII table")

/* clang-format off */
struct ttable_style ttable_styles[] = {
	{	// default ascii
		.corner = '+',
		.rownums_on = false,
		.indent = 1,
		.border = {
			.top = '-',
			.bottom = '-',
			.left = '|',
			.right = '|',
			.top_on = true,
			.bottom_on = true,
			.left_on = true,
			.right_on = true,
		},
		.cell = {
			.lpad = 1,
			.rpad = 1,
			.align = LEFT,
			.border = {
				.bottom = '-',
				.bottom_on = true,
				.top = '-',
				.top_on = false,
				.right = '|',
				.right_on = true,
				.left = '|',
				.left_on = false,
			},
		},
	}, {	// blank, suitable for plaintext alignment
		.corner = ' ',
		.rownums_on = false,
		.indent = 1,
		.border = {
			.top = ' ',
			.bottom = ' ',
			.left = ' ',
			.right = ' ',
			.top_on = false,
			.bottom_on = false,
			.left_on = false,
			.right_on = false,
		},
		.cell = {
			.lpad = 0,
			.rpad = 3,
			.align = LEFT,
			.border = {
				.bottom = ' ',
				.bottom_on = false,
				.top = ' ',
				.top_on = false,
				.right = ' ',
				.right_on = false,
				.left = ' ',
				.left_on = false,
			},
		}
   }
};
/* clang-format on */

void ttable_del(struct ttable *tt)
{
	for (int i = tt->nrows - 1; i >= 0; i--)
		ttable_del_row(tt, i);

	XFREE(MTYPE_TTABLE, tt->table);
	XFREE(MTYPE_TTABLE, tt);
}

struct ttable *ttable_new(struct ttable_style *style)
{
	struct ttable *tt;

	tt = XCALLOC(MTYPE_TTABLE, sizeof(struct ttable));
	tt->style = *style;
	tt->nrows = 0;
	tt->ncols = 0;
	tt->size = 0;
	tt->table = NULL;

	return tt;
}

/**
 * Inserts or appends a new row at the specified index.
 *
 * If the index is -1, the row is added to the end of the table. Otherwise the
 * index must be a valid index into tt->table.
 *
 * If the table already has at least one row (and therefore a determinate
 * number of columns), a format string specifying a number of columns not equal
 * to tt->ncols will result in a no-op and a return value of NULL.
 *
 * @param tt table to insert into
 * @param i insertion index; inserted row will be (i + 1)'th row
 * @param format printf format string as in ttable_[add|insert]_row()
 * @param ap pre-initialized variadic list of arguments for format string
 *
 * @return pointer to the first cell of allocated row
 */
static struct ttable_cell *ttable_insert_row_va(struct ttable *tt, int i,
						const char *format, va_list ap)
{
	assert(i >= -1 && i < tt->nrows);

	char *res, *orig, *section;
	struct ttable_cell *row;
	int col = 0;
	int ncols = 0;

	/* count how many columns we have */
	for (int i = 0; format[i]; i++)
		ncols += !!(format[i] == '|');
	ncols++;

	if (tt->ncols == 0)
		tt->ncols = ncols;
	else if (ncols != tt->ncols)
		return NULL;

	/* reallocate chunk if necessary */
	while (tt->size < (tt->nrows + 1) * sizeof(struct ttable_cell *)) {
		tt->size = MAX(2 * tt->size, 2 * sizeof(struct ttable_cell *));
		tt->table = XREALLOC(MTYPE_TTABLE, tt->table, tt->size);
	}

	/* CALLOC a block of cells */
	row = XCALLOC(MTYPE_TTABLE, tt->ncols * sizeof(struct ttable_cell));

	res = NULL;
	vasprintf(&res, format, ap);

	orig = res;

	while (res) {
		section = strsep(&res, "|");
		row[col].text = XSTRDUP(MTYPE_TTABLE, section);
		row[col].style = tt->style.cell;
		col++;
	}

	free(orig);

	/* insert row */
	if (i == -1 || i == tt->nrows)
		tt->table[tt->nrows] = row;
	else {
		memmove(&tt->table[i + 1], &tt->table[i],
			(tt->nrows - i) * sizeof(struct ttable_cell *));
		tt->table[i] = row;
	}

	tt->nrows++;

	return row;
}

struct ttable_cell *ttable_insert_row(struct ttable *tt, unsigned int i,
				      const char *format, ...)
{
	struct ttable_cell *ret;
	va_list ap;

	va_start(ap, format);
	ret = ttable_insert_row_va(tt, i, format, ap);
	va_end(ap);

	return ret;
}

struct ttable_cell *ttable_add_row(struct ttable *tt, const char *format, ...)
{
	struct ttable_cell *ret;
	va_list ap;

	va_start(ap, format);
	ret = ttable_insert_row_va(tt, -1, format, ap);
	va_end(ap);

	return ret;
}

void ttable_del_row(struct ttable *tt, unsigned int i)
{
	assert((int)i < tt->nrows);

	for (int j = 0; j < tt->ncols; j++)
		XFREE(MTYPE_TTABLE, tt->table[i][j].text);

	XFREE(MTYPE_TTABLE, tt->table[i]);

	memmove(&tt->table[i], &tt->table[i + 1],
		(tt->nrows - i - 1) * sizeof(struct ttable_cell *));

	tt->nrows--;

	if (tt->nrows == 0)
		tt->ncols = 0;
}

void ttable_align(struct ttable *tt, unsigned int row, unsigned int col,
		  unsigned int nrow, unsigned int ncol, enum ttable_align align)
{
	assert((int)row < tt->nrows);
	assert((int)col < tt->ncols);
	assert((int)row + (int)nrow <= tt->nrows);
	assert((int)col + (int)ncol <= tt->ncols);

	for (unsigned int i = row; i < row + nrow; i++)
		for (unsigned int j = col; j < col + ncol; j++)
			tt->table[i][j].style.align = align;
}

static void ttable_cell_pad(struct ttable_cell *cell, enum ttable_align align,
			    short pad)
{
	if (align == LEFT)
		cell->style.lpad = pad;
	else
		cell->style.rpad = pad;
}

void ttable_pad(struct ttable *tt, unsigned int row, unsigned int col,
		unsigned int nrow, unsigned int ncol, enum ttable_align align,
		short pad)
{
	assert((int)row < tt->nrows);
	assert((int)col < tt->ncols);
	assert((int)row + (int)nrow <= tt->nrows);
	assert((int)col + (int)ncol <= tt->ncols);

	for (unsigned int i = row; i < row + nrow; i++)
		for (unsigned int j = col; j < col + ncol; j++)
			ttable_cell_pad(&tt->table[i][j], align, pad);
}

void ttable_restyle(struct ttable *tt)
{
	for (int i = 0; i < tt->nrows; i++)
		for (int j = 0; j < tt->ncols; j++)
			tt->table[i][j].style = tt->style.cell;
}

void ttable_colseps(struct ttable *tt, unsigned int col,
		    enum ttable_align align, bool on, char sep)
{
	for (int i = 0; i < tt->nrows; i++) {
		if (align == RIGHT) {
			tt->table[i][col].style.border.right_on = on;
			tt->table[i][col].style.border.right = sep;
		} else {
			tt->table[i][col].style.border.left_on = on;
			tt->table[i][col].style.border.left = sep;
		}
	}
}

void ttable_rowseps(struct ttable *tt, unsigned int row,
		    enum ttable_align align, bool on, char sep)
{
	for (int i = 0; i < tt->ncols; i++) {
		if (align == TOP) {
			tt->table[row][i].style.border.top_on = on;
			tt->table[row][i].style.border.top = sep;
		} else {
			tt->table[row][i].style.border.bottom_on = on;
			tt->table[row][i].style.border.bottom = sep;
		}
	}
}

char *ttable_dump(struct ttable *tt, const char *newline)
{
	/* clang-format off */
	char *buf;	   // print buffer
	size_t pos;	   // position in buffer
	size_t nl_len;     // strlen(newline)
	int cw[tt->ncols]; // calculated column widths
	int nlines;	   // total number of newlines / table lines
	size_t width;      // length of one line, with newline
	int abspad;	   // calculated whitespace for sprintf
	char *left;	   // left part of line
	size_t lsize;	   // size of above
	char *right;	   // right part of line
	size_t rsize;	   // size of above
	struct ttable_cell *cell, *row; // iteration pointers
	/* clang-format on */

	nl_len = strlen(newline);

	/* calculate width of each column */
	memset(cw, 0x00, sizeof(int) * tt->ncols);

	for (int j = 0; j < tt->ncols; j++)
		for (int i = 0, cellw = 0; i < tt->nrows; i++) {
			cell = &tt->table[i][j];
			cellw = 0;
			cellw += (int)strlen(cell->text);
			cellw += cell->style.lpad;
			cellw += cell->style.rpad;
			if (j != 0)
				cellw += cell->style.border.left_on ? 1 : 0;
			if (j != tt->ncols - 1)
				cellw += cell->style.border.right_on ? 1 : 0;
			cw[j] = MAX(cw[j], cellw);
		}

	/* calculate overall line width, including newline */
	width = 0;
	width += tt->style.indent;
	width += tt->style.border.left_on ? 1 : 0;
	width += tt->style.border.right_on ? 1 : 0;
	width += strlen(newline);
	for (int i = 0; i < tt->ncols; i++)
		width += cw[i];

	/* calculate number of lines en total */
	nlines = tt->nrows;
	nlines += tt->style.border.top_on ? 1 : 0;
	nlines += 1; // tt->style.border.bottom_on ? 1 : 1; makes life easier
	for (int i = 0; i < tt->nrows; i++) {
		/* if leftmost cell has top / bottom border, whole row does */
		nlines += tt->table[i][0].style.border.top_on ? 1 : 0;
		nlines += tt->table[i][0].style.border.bottom_on ? 1 : 0;
	}

	/* initialize left & right */
	lsize = tt->style.indent + (tt->style.border.left_on ? 1 : 0);
	left = XCALLOC(MTYPE_TTABLE, lsize);
	rsize = nl_len + (tt->style.border.right_on ? 1 : 0);
	right = XCALLOC(MTYPE_TTABLE, rsize);

	memset(left, ' ', lsize);

	if (tt->style.border.left_on)
		left[lsize - 1] = tt->style.border.left;

	if (tt->style.border.right_on) {
		right[0] = tt->style.border.right;
		memcpy(&right[1], newline, nl_len);
	} else
		memcpy(&right[0], newline, nl_len);

	/* allocate print buffer */
	buf = XCALLOC(MTYPE_TMP, width * (nlines + 1) + 1);
	pos = 0;

	if (tt->style.border.top_on) {
		memcpy(&buf[pos], left, lsize);
		pos += lsize;

		for (size_t i = 0; i < width - lsize - rsize; i++)
			buf[pos++] = tt->style.border.top;

		memcpy(&buf[pos], right, rsize);
		pos += rsize;
	}

	for (int i = 0; i < tt->nrows; i++) {
		row = tt->table[i];

		/* if top border and not first row, print top row border */
		if (row[0].style.border.top_on && i != 0) {
			memcpy(&buf[pos], left, lsize);
			pos += lsize;

			for (size_t i = 0; i < width - lsize - rsize; i++)
				buf[pos++] = row[0].style.border.top;

			pos -= width - lsize - rsize;
			for (int k = 0; k < tt->ncols; k++) {
				if (k != 0 && row[k].style.border.left_on)
					buf[pos] = tt->style.corner;
				pos += cw[k];
				if (row[k].style.border.right_on
				    && k != tt->ncols - 1)
					buf[pos - 1] = tt->style.corner;
			}

			memcpy(&buf[pos], right, rsize);
			pos += rsize;
		}

		memcpy(&buf[pos], left, lsize);
		pos += lsize;

		for (int j = 0; j < tt->ncols; j++) {
			/* if left border && not first col print left border */
			if (row[j].style.border.left_on && j != 0)
				buf[pos++] = row[j].style.border.left;

			/* print left padding */
			for (int i = 0; i < row[j].style.lpad; i++)
				buf[pos++] = ' ';

			/* calculate padding for sprintf */
			abspad = cw[j];
			abspad -= row[j].style.rpad;
			abspad -= row[j].style.lpad;
			if (j != 0)
				abspad -= row[j].style.border.left_on ? 1 : 0;
			if (j != tt->ncols - 1)
				abspad -= row[j].style.border.right_on ? 1 : 0;

			/* print text */
			const char *fmt;
			if (row[j].style.align == LEFT)
				fmt = "%-*s";
			else
				fmt = "%*s";

			pos += sprintf(&buf[pos], fmt, abspad, row[j].text);

			/* print right padding */
			for (int i = 0; i < row[j].style.rpad; i++)
				buf[pos++] = ' ';

			/* if right border && not last col print right border */
			if (row[j].style.border.right_on && j != tt->ncols - 1)
				buf[pos++] = row[j].style.border.right;
		}

		memcpy(&buf[pos], right, rsize);
		pos += rsize;

		/* if bottom border and not last row, print bottom border */
		if (row[0].style.border.bottom_on && i != tt->nrows - 1) {
			memcpy(&buf[pos], left, lsize);
			pos += lsize;

			for (size_t i = 0; i < width - lsize - rsize; i++)
				buf[pos++] = row[0].style.border.bottom;

			pos -= width - lsize - rsize;
			for (int k = 0; k < tt->ncols; k++) {
				if (k != 0 && row[k].style.border.left_on)
					buf[pos] = tt->style.corner;
				pos += cw[k];
				if (row[k].style.border.right_on
				    && k != tt->ncols - 1)
					buf[pos - 1] = tt->style.corner;
			}

			memcpy(&buf[pos], right, rsize);
			pos += rsize;
		}

		assert(!buf[pos]); /* pos == & of first \0 in buf */
	}

	if (tt->style.border.bottom_on) {
		memcpy(&buf[pos], left, lsize);
		pos += lsize;

		for (size_t i = 0; i < width - lsize - rsize; i++)
			buf[pos++] = tt->style.border.bottom;

		memcpy(&buf[pos], right, rsize);
		pos += rsize;
	}

	buf[pos] = '\0';

	XFREE(MTYPE_TTABLE, left);
	XFREE(MTYPE_TTABLE, right);

	return buf;
}
