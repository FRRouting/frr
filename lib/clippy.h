// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * clippy (CLI preparator in python)
 * Copyright (C) 2016-2017  David Lamparter for NetDEF, Inc.
 */

#ifndef _FRR_CLIPPY_H
#define _FRR_CLIPPY_H

#include <stdbool.h>
#include <Python.h>

#ifdef __cplusplus
extern "C" {
#endif

extern PyObject *clippy_parse(PyObject *self, PyObject *args);
extern PyMODINIT_FUNC command_py_init(void);
extern bool elf_py_init(PyObject *pymod);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_CLIPPY_H */
