// SPDX-License-Identifier: GPL-2.0-or-later
//
// September 9 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//

pub mod c_shim;
#[macro_use]
pub mod frrutil;

use std::ffi::c_void;
use std::io::Result;
use std::sync::OnceLock;

use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, error};

// -------
// Globals
// -------

enum Command {
    Quit,
}

static TX: OnceLock<Sender<Command>> = OnceLock::new();
static RX: OnceLock<std::sync::Mutex<Receiver<Result<()>>>> = OnceLock::new();

////
/// Get an tokio runtime for async execution
///
/// This function should create a runtime for the daemon. The generic rust infra
/// code will call it to create the runtime for the daemon. The runtime will be
/// passed to `rust_run()` so that a main task (or whatever) can be started.
fn get_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .on_thread_start(|| {
            frrutil::frr_register_thread("tokio-worker-thread");
            debug!("tokio thread started")
        })
        .on_thread_stop(|| debug!("tokio thread stop"))
        .enable_all()
        .build()
        .unwrap()
}

// ===================================================
// Initialization/Teardown Callbacks (from xxx_main.c)
// ===================================================

///
/// Pre-init (called after frr_preinit()), returned value is passed to rust_init()
fn rust_preinit(_daemon: *mut c_shim::frr_daemon_info) -> *mut c_void {
    debug!("in rust_preinit");
    std::ptr::null_mut()
}

///
/// Pre-daemonize (called after frr_init()), returned value is passed to rust_run()
fn rust_init(_preinit_val: *mut c_void) -> *mut c_void {
    debug!("in rust_init");
    std::ptr::null_mut()
}

///
/// Called prior to entering the FRR event loop (frr_run())
///
/// This function should spawn a task into the tokio runtime to run the daemon
fn rust_run(runtime: &mut tokio::runtime::Runtime, _init_val: *mut c_void) -> *mut c_void {
    debug!("in rust_run");

    //
    // Setup command channel with async_main thread
    //

    let (tx, rx) = channel::<Command>(10);
    let (result_tx, result_rx) = channel::<Result<()>>(10);
    TX.set(tx.clone()).expect("only set once");
    RX.set(std::sync::Mutex::new(result_rx))
        .expect("only set once");

    //
    // Start running our main routine
    //
    runtime.spawn(async { async_main(rx, result_tx).await });
    std::ptr::null_mut()
}

///
/// FRR exiting callback
///
/// Do any cleanup prior to the rust runtime being dropped and all spawned tasks
/// being joined/canceled.
pub fn rust_fini(_run_val: *mut c_void) {
    debug!("rust_fini: sending quit command to async_main");
    if TX.get().unwrap().blocking_send(Command::Quit).is_err() {
        return;
    }

    debug!("rust_fini: waiting on exit result from async_main");
    if let Some(result) = RX.get().unwrap().lock().unwrap().blocking_recv() {
        match result {
            Ok(()) => debug!("Runtime quit successfully"),
            Err(x) => error!("Failed to quit runtime: {}", x),
        }
    }
}

// ============================
// Main Rust Execution Function
// ============================

///
/// Main loop -- process commands from FRR
async fn async_main(mut cmd_rx: Receiver<Command>, result_tx: Sender<Result<()>>) {
    loop {
        debug!("Waiting on cmd channel");
        let cmd = match cmd_rx.recv().await {
            None => continue,
            Some(cmd) => cmd,
        };
        match cmd {
            Command::Quit => {
                debug!("Quit command");
                let _ = result_tx.send(Ok(())).await;
                return;
            }
        }
    }
}
