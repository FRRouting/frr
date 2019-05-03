/*
 * clippy (CLI preparator in python)
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

#ifndef _FRR_CLIPPY_H
#define _FRR_CLIPPY_H

#include <Python.h>

#ifdef __cplusplus
extern "C" {
#endif

extern PyObject *clippy_parse(PyObject *self, PyObject *args);
extern PyMODINIT_FUNC command_py_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_CLIPPY_H */
