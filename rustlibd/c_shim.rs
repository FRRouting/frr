// SPDX-License-Identifier: GPL-2.0-or-later
//
// September 22 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (c) 2024, LabN Consulting, L.L.C.
//
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::c_void;

struct ShimGlobals {
    arg: *mut c_void,
    runtime: tokio::runtime::Runtime,
}

#[no_mangle]
pub extern "C" fn _rust_preinit(daemon: *mut frr_daemon_info) -> *mut c_void {
    crate::rust_preinit(daemon)
}

#[no_mangle]
pub extern "C" fn _rust_init(_master: *mut event_loop, arg: *mut c_void) -> *mut c_void {
    crate::rust_init(arg)
}

#[no_mangle]
pub extern "C" fn _rust_run(_master: *mut event_loop, arg: *mut c_void) -> *mut c_void {
    let runtime = crate::get_runtime();

    let mut globals = Box::new(ShimGlobals {
        arg: crate::rust_init(arg),
        runtime,
    });

    globals.arg = crate::rust_run(&mut globals.runtime, globals.arg);

    Box::into_raw(globals) as *mut c_void
}

#[no_mangle]
pub extern "C" fn _rust_fini(_master: *mut event_loop, arg: *mut c_void) {
    let globals = unsafe { Box::from_raw(arg as *mut ShimGlobals) };

    crate::rust_fini(globals.arg);

    // Make this explicit, not really needed but makes it clear
    drop(globals.runtime);
}
