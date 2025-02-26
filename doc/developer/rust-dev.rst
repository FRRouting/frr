.. -*- coding: utf-8 -*-
..
.. SPDX-License-Identifier: GPL-2.0-or-later
..
.. February 26 2025, Christian Hopps <chopps@labn.net>
..
.. Copyright (c) 2025, LabN Consulting, L.L.C.
..

.. _rust_dev:

Rust Development
================

Overview
--------

The FRR project has started adding support for daemons written in rust. The
following sections document the infrastructure to support to-date. This is the
initial approach of rust integration, we expect changes as best-practices within
the community evolve.

General Structure
-----------------

An example template of the general structure of a rust based daemon can be found
in ``rustlib/`` sub-directory. The recommended structure so far is to use a C
main file and function to drive initialization of the daemon calling out to rust
at 3 critical points. The Rust code is then built as a static library and linked
into the daemon. Rust bindings are built for ``libfrr`` and accessed through a
c_shim sub-module. Here's the files and as of the time of this writing:

.. code-block:: make

rustlibd/
    .gitignore
    Cargo.toml.in
    Makefile
    README.org
    build.rs.in
    c_shim.rs
    frrutil.rs (symlink)
    rustlib_lib.rs
    rustlib_main.c
    sandbox.rs
    subdir.am
    wrapper.h.in

:file:`frrutil.rs` is a symlink to :file:`../lib/frrutil.rs` kept here to keep
various rust tools happy about files being inside or below the main source
directory.


NOTE: if you use a separate build dir (named `build` in the below example) and
you want to have your development environment proper analyze code (e.g.,
vs-code/emacs LSP mode) you should create an additional 2 symlinks and create a
local :file:`Cargo.toml` file like so:

.. code-block:: sh

    cd frr/rustlibd
    sed -e 's,@srcdir@/,,g' < Cargo.toml.in > Cargo.toml
    ln -s ../build/rustlibd/build.rs .
    ln -s ../build/rustlibd/wrapper.h .

Logging
-------

FRR logging is transparently supported using some bridging code that connects
the native rust ``tracing`` calls directly to the ``zlog`` functionality in FRR.
The only thing you have to do is call the function :func:`bridge_rust_logging`
at startup. This is already done for you in the `rustlibd` template :func:`main`
if you started with that code.

.. code-block:: rust

    use tracing::{debug, info};

    fn myrustfunc(sval: &str, uval: u32) {
       debug!("Some DEBUG level output of str value: {}", sval);
       info!("Some INFO level output of uint value: {}", uval);
    }

Northbound Integration
----------------------

Support for the FRR northbound callback system is handled through rust macros.
These rust macros define C shims which then call your rust functions which will
use natural rust types. The rust macros hide the unsafe and tricky conversion
code. You put pointers to the generated C shim functions into the
:struct:`frr_yang_module_info` structure.

NOTE: Locking will probably be important as your callbacks will be called in the
FRR event loop main thread and your rust code is probably running in it's own
different thread (perhaps using the tokio async runtime as setup in the
:file:`rustlibd` template).

Here's an example of defining a handler for a config leave value `enable`:

.. code-block:: C

    const struct frr_yang_module_info frr_my_module_nb_info = {
	.name = "frr-my-module",
	.nodes = {
		{
			.xpath = "/frr-my-module:lib/bvalue",
			.cbs = {
				.modify = my_module_bvalue_modify_shim,
				.destroy = my_module_bvalue_destroy_shim
			}
		},
                ...

.. code-block:: rust

    use crate::{define_nb_destroy_shim, define_nb_modify_shim};

    pub(crate) fn my_module_bvalue_modify(
        event: NbEvent,
        _node: &DataNodeRef,
    ) -> Result<(), nb_error> {
        debug!("RUST: bvalue modify: {}", event);
        match event {
            NbEvent::APPLY(_) => {
                // handle the change to the `bvalue` leaf.
                Ok(())
            },
            _ => Ok(()), // All other events just return Ok.
        }
    }

    pub(crate) fn my_module_bvalue_destroy(
        event: NbEvent,
        _node: &DataNodeRef,
    ) -> Result<(), nb_error> {
        // handle the removal of the `bvalue` leaf.
        // ...
    }

    define_nb_modify_shim!(
        my_module_bvalue_modify_shim,
        my_module_bvalue_modify);

    define_nb_destroy_shim!(
        my_module_bvalue_destroy_shim,
        my_module_bvalue_destroy);


CLI commands
~~~~~~~~~~~~

For CLI commands you should continue to write the DEFPY_YANG() calls in C which
simply set your YANG config data base on the args to DEFPY_YANG(). The actual
configuration will be handled in your rust based callbacks you defined for your
YANG model that are describe above.

Operational State
~~~~~~~~~~~~~~~~~

You have 2 choices with operation state. You can implement the operation state
callbacks in rust and use the rust macros to bridge these to the
:struct:`frr_yang_module_info` definition as you did with your config handlers, or you
can keep your operational state in a ``yang-rs`` (i.e., ``libyang``) based tree.
Here's an example of using the macros:

If you choose to do the latter and save all your operational state in a
``libyang`` :struct:`DataTree`, you only need to define 2 callback functions, a
:func:`get_tree_locked()` function which returns the :struct:`DataTree` in a
:struct:`MutexGuard` (i.e., a held lock), and an :func:`unlock_tree()` function
which is passed back the :struct:`MutexGuard` object for unlocking. You use 2
macros: :func:`define_nb_get_tree_locked`, and :func:`define_nb_unlock_tree` to
create the C based shims to plug into your :struct:`frr_yang_module_info`
structure.

NOTE: As with config, locking will probably be important as your callbacks will
be called in the FRR event loop main thread and your rust code is probably
running in it's own different thread.
