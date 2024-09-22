// SPDX-License-Identifier: GPL-2.0-or-later
//
// September 9 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// #[path = "rust_server.rs"]
// pub mod rust;
// Need to figure best way to do shared source files
// #[path = "../lib/rust_msg.rs"]
// pub mod msg;

use tracing::debug;

extern "C" {
    // This is our C init function we use to handle the complex compiler tricks
    // FRR uses for initializing the daemon info structure.
    fn rust_get_daemon_info() -> *mut frr_daemon_info;
}

///
/// Setup the trace logging.
///
fn setup_logging() {
    /*
     * Enable some logging
     */
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

///
/// Main Function :)
///
fn main() {
    setup_logging();

    // Initialize FRR.

    // create a vector of zero terminated CLI arg strings
    let args = std::env::args()
        .map(|arg| CString::new(arg).unwrap())
        .collect::<Vec<CString>>();

    // convert the strings to raw pointers
    let c_args = args
        .iter()
        .map(|arg| arg.as_ptr())
        .collect::<Vec<*const c_char>>();

    // Get frr_daemon_info from our C init module
    let di = unsafe { rust_get_daemon_info() };

    // Initialize FRR
    unsafe { frr_preinit(di, c_args.len() as i32, c_args.as_ptr() as *mut *mut i8) }

    debug!("daemon name is {:?}", unsafe {
        CStr::from_ptr((*di).progname)
    });

    let master = unsafe { frr_init() };
    debug!("master thread: {:?}", master);

    // Run!
    debug!("Running main FRR loop");
    unsafe { frr_run(master) };
}
