// -*- coding: utf-8 -*-
// SPDX-License-Identifier: GPL-2.0-or-later
//
// January 25 2025, Christian Hopps <chopps@labn.net>
//
// Copyright (c) 2025, LabN Consulting, L.L.C.
//
use std::ffi::CStr;
use std::ffi::CString;
use std::io::Write;
use std::os::raw::{c_char, c_int, c_void};
use std::string::String;

use lazy_static::lazy_static;
use tracing::error;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::prelude::*;
use yang::data::{DataNodeRef, DataTreeOwningRef};
use yang::ffi;
use yang::utils::Binding;

/// Module implementing FRR rust utilities
use crate::c_shim;
use crate::c_shim::{ly_native_ctx, nb_error, nb_error_NB_ERR, nb_error_NB_OK};

// -----------------------
// Module Static Variables
// -----------------------

lazy_static! {
    pub static ref FRR_YANG_CTX: yang::context::Context = {
        unsafe {
            let _frr_ctx = ly_native_ctx as *mut ffi::ly_ctx;
            yang::context::Context::from_raw(&(), _frr_ctx)
        }
    };
}

// ----------------------
// Module Private Utility
// ----------------------

pub fn validate_p<T>(p: *const T) -> &'static T {
    if p.is_null() {
        panic!("Null pointer when needing a reference");
    }
    unsafe { &*p }
}

pub fn validate_mp<T>(p: *mut T) -> &'static mut T {
    if p.is_null() {
        panic!("Null pointer when needing a reference");
    }
    unsafe { &mut *p }
}

fn u8_to_char(slice: &[u8]) -> &[c_char] {
    unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const c_char, slice.len()) }
}

// ==========
// Northbound
// ==========

// ----------------
// Northbound Enums
// ----------------

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum NbError {
    Ok = c_shim::nb_error_NB_OK as u8,
    Err = c_shim::nb_error_NB_ERR as u8,
    NoChanges = c_shim::nb_error_NB_ERR_NO_CHANGES as u8,
    NotFound = c_shim::nb_error_NB_ERR_NOT_FOUND as u8,
    Exists = c_shim::nb_error_NB_ERR_EXISTS as u8,
    Locked = c_shim::nb_error_NB_ERR_LOCKED as u8,
    Validation = c_shim::nb_error_NB_ERR_VALIDATION as u8,
    Resource = c_shim::nb_error_NB_ERR_RESOURCE as u8,
    Yield = c_shim::nb_error_NB_YIELD as u8,
}

impl std::fmt::Display for NbError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

impl std::error::Error for NbError {}

#[derive(Copy, Clone, Debug)]
pub enum NbEvent {
    VALIDATE,
    PREPARE,
    ABORT(*mut c_void),
    APPLY(*mut c_void),
}

impl std::fmt::Display for NbEvent {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

pub fn nb_event_to_rust(c_event: c_shim::nb_event, arg: *mut c_void) -> NbEvent {
    match c_event {
        c_shim::nb_event_NB_EV_VALIDATE => NbEvent::VALIDATE,
        c_shim::nb_event_NB_EV_PREPARE => NbEvent::PREPARE,
        c_shim::nb_event_NB_EV_ABORT => NbEvent::ABORT(arg),
        c_shim::nb_event_NB_EV_APPLY => NbEvent::APPLY(arg),
        _ => panic!("invalid northbound event: {}", c_event),
    }
}

// -----------------------
// Northbound API Adapters
// -----------------------

pub fn nb_notify_update(path: &str) {
    let cstr = CString::new(path).expect("Failed to convert string to c-string");

    unsafe { c_shim::nb_notif_add(cstr.as_ptr()) };
}

pub fn nb_notify_update_node(node: &DataNodeRef) {
    let path = node.path();

    nb_notify_update(&path);
}

pub fn nb_notify_delete(path: &str) {
    let cstr = CString::new(path).expect("Failed to convert string to c-string");

    unsafe { c_shim::nb_notif_delete(cstr.as_ptr()) };
}

pub fn nb_notify_delete_node(node: &DataNodeRef) {
    let path = node.path();

    nb_notify_delete(&path);
}

// -------------------------
// Northbound Callback Shims
// -------------------------

/// Obtain a temporary DataTreeOwningRef from a mutable lyd_node pointer.
///
/// Safety: The user needs to be careful if actually constructing this from a
/// const lyd_node pointer to only pass on non-mut references to the object or
/// it's noderef().
pub fn new_borrowed_node<'a>(
    parent: *mut ffi::lyd_node,
) -> std::mem::ManuallyDrop<DataTreeOwningRef<'a>> {
    unsafe { DataTreeOwningRef::from_raw_node(&FRR_YANG_CTX, parent) }
}

pub fn nb_create_shim(
    _args: *mut c_shim::nb_cb_create_args,
    create: fn(NbEvent, &DataNodeRef) -> Result<(), nb_error>,
) -> nb_error {
    let args = validate_p(_args);
    let resource_ptr = if args.resource.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { validate_p(args.resource).ptr }
    };
    let event = nb_event_to_rust(args.event, resource_ptr);
    let node = new_borrowed_node(args.dnode as *mut ffi::lyd_node);
    match create(event, &node.noderef()) {
        Ok(()) => nb_error_NB_OK,
        Err(e) => e,
    }
}

#[macro_export]
macro_rules! define_nb_create_shim {
    ($shim_name:ident, $native_func:expr) => {
        #[no_mangle]
        extern "C" fn $shim_name(
            args: *mut $crate::c_shim::nb_cb_create_args,
        ) -> $crate::c_shim::nb_error {
            $crate::frrutil::nb_create_shim(args, $native_func)
        }
    };
}

pub fn nb_destroy_shim(
    _args: *mut c_shim::nb_cb_destroy_args,
    destroy: fn(NbEvent, &DataNodeRef) -> Result<(), nb_error>,
) -> nb_error {
    let args = validate_p(_args);
    let event = nb_event_to_rust(args.event, std::ptr::null_mut());
    let node = new_borrowed_node(args.dnode as *mut ffi::lyd_node);
    match destroy(event, &node.noderef()) {
        Ok(()) => nb_error_NB_OK,
        Err(e) => e,
    }
}

#[macro_export]
macro_rules! define_nb_destroy_shim {
    ($shim_name:ident, $native_func:expr) => {
        #[no_mangle]
        extern "C" fn $shim_name(
            args: *mut $crate::c_shim::nb_cb_destroy_args,
        ) -> $crate::c_shim::nb_error {
            $crate::frrutil::nb_destroy_shim(args, $native_func)
        }
    };
}

pub fn nb_modify_shim(
    _args: *mut c_shim::nb_cb_modify_args,
    modify: fn(NbEvent, &DataNodeRef) -> Result<(), nb_error>,
) -> nb_error {
    let args = validate_p(_args);
    let resource_ptr = if args.resource.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { validate_p(args.resource).ptr }
    };
    let event = nb_event_to_rust(args.event, resource_ptr);
    let node = new_borrowed_node(args.dnode as *mut ffi::lyd_node);
    match modify(event, &node.noderef()) {
        Ok(()) => nb_error_NB_OK,
        Err(e) => e,
    }
}

#[macro_export]
macro_rules! define_nb_modify_shim {
    ($shim_name:ident, $native_func:expr) => {
        #[no_mangle]
        extern "C" fn $shim_name(
            args: *mut $crate::c_shim::nb_cb_modify_args,
        ) -> $crate::c_shim::nb_error {
            $crate::frrutil::nb_modify_shim(args, $native_func)
        }
    };
}

/// Generic get_keys code to translate C callback args to and from native Rust.
pub fn nb_get_keys_shim(
    _args: *mut c_shim::nb_cb_get_keys_args,
    get_keys: fn(*const c_void) -> Result<Vec<String>, c_int>,
) -> c_int {
    let args = validate_mp(_args);
    let list_entry = args.list_entry;
    let keys_ret = validate_mp(args.keys);

    let keys = match get_keys(list_entry) {
        Err(e) => return e as c_int,
        Ok(keys) => keys,
    };

    let num_keys = keys.len();
    if num_keys > keys_ret.key.len() {
        panic!(
            "Too many keys for list entry: {} > {}",
            num_keys,
            keys_ret.key.len()
        );
    }

    // Walk vector of keys
    keys_ret.num = num_keys as u8;
    for (index, value) in keys.iter().enumerate() {
        let keyref = &mut keys_ret.key[index];
        let vlen = value.len();
        if vlen >= keyref.len() {
            error!(
                "key '{}' is too long to store: {} > {}",
                value,
                vlen + 1,
                keyref.len()
            );
            return nb_error_NB_ERR as c_int;
        }
        // Copy the key data as NUL terminated C-string.
        keyref[..vlen].copy_from_slice(u8_to_char(value.as_bytes()));
        keyref[vlen] = 0;
    }

    nb_error_NB_OK as std::os::raw::c_int
}

#[macro_export]
macro_rules! define_nb_get_keys_shim {
    ($shim_name:ident, $native_func:ident) => {
        #[no_mangle]
        pub extern "C" fn $shim_name(_args: *mut c_shim::nb_cb_get_keys_args) -> c_int {
            frrutil::nb_get_keys_shim(_args, $native_func)
        }
    };
}

#[macro_export]
macro_rules! define_nb_get_shim {
    ($shim_name:ident, $native_func:expr) => {
        #[no_mangle]
        pub extern "C" fn $shim_name(
            _nb_node: *const nb_node,
            parent_list_item: *const c_void,
            _parent: *mut lyd_node,
        ) -> nb_error {
            let parent = frrutil::new_borrowed_node(_parent as *mut ffi::lyd_node);
            match $native_func(parent_list_item, &mut parent.noderef()) {
                Ok(e) => e,
                Err(_) => nb_error_NB_ERR,
            }
        }
    };
}

#[macro_export]
macro_rules! define_nb_get_next_shim {
    ($shim_name:ident, $native_func:expr) => {
        #[no_mangle]
        extern "C" fn $shim_name(args: *mut c_shim::nb_cb_get_next_args) -> *const c_void {
            let args = frrutil::validate_p(args);
            $native_func(args.parent_list_entry, args.list_entry)
        }
    };
}

pub fn nb_lookup_entry_shim(
    _args: *mut c_shim::nb_cb_lookup_entry_args,
    lookup_entry: fn(_parent_list_entry: *const c_void, _keys: &[&CStr]) -> *const c_void,
) -> *const c_void {
    let args = validate_p(_args);
    let c_keys = validate_p(args.keys);
    let num_keys = c_keys.num as usize;
    let mut keys = Vec::<&CStr>::with_capacity(num_keys);
    for i in 0..num_keys {
        let key = unsafe { CStr::from_ptr(c_keys.key[i].as_ptr()) };
        keys.push(key);
    }
    lookup_entry(args.parent_list_entry, &keys)
}

#[macro_export]
macro_rules! define_nb_lookup_entry_shim {
    ($shim_name:ident, $native_func:expr) => {
        #[no_mangle]
        extern "C" fn $shim_name(_args: *mut c_shim::nb_cb_lookup_entry_args) -> *const c_void {
            frrutil::nb_lookup_entry_shim(_args, $native_func)
        }
    };
}

// #[macro_export]
// macro_rules! define_nb_get_tree_locked {
//     ($shim_name:ident, $native_func:expr) => {
//         #[no_mangle]
//         extern "C" fn $shim_name(xpath: *const c_char, lockptr: **c_void) -> *const c_shim::lyd_node {
//             if xpath.is_null() {
//                 return std::ptr::null() as *const c_shim::lyd_node;
//             }
//             let xpath_cstr = unsafe { CStr::from_ptr(xpath) };
//             let xpath = xpath_cstr.to_owned();
//             let (tree_ptr, leaked_lock_ptr) = $native_func(&xpath);
//             unsafe { *lockptr = leaked_lock };
//             ???
//         }
//     };
// }

#[macro_export]
macro_rules! define_nb_get_tree_locked {
    ($shim_name:ident, $native_func:expr) => {
        #[no_mangle]
        extern "C" fn $shim_name(
            xpath: *const c_char,
            lockptr: *mut *const c_void,
        ) -> *const c_shim::lyd_node {
            if xpath.is_null() || lockptr.is_null() {
                return std::ptr::null();
            }
            let xpath_cstr = unsafe { CStr::from_ptr(xpath) };
            let xpath = xpath_cstr.to_owned();

            let guard = $native_func(&xpath);
            let tree = (*guard).raw();
            let raw_guard = Box::into_raw(Box::new(guard)) as *const c_void;
            unsafe { *lockptr = raw_guard };
            tree as *const c_shim::lyd_node
        }
    };
}

#[macro_export]
macro_rules! define_nb_unlock_tree {
    ($shim_name:ident, $native_func:expr) => {
        #[no_mangle]
        extern "C" fn $shim_name(_tree: *const c_shim::lyd_node, lock: *const c_void) {
            let raw_guard =
                lock as *mut tokio::sync::MutexGuard<'static, yang3::data::DataTree<'_>>;
            let guard = unsafe { Box::<MutexGuard<'static, DataTree<'_>>>::from_raw(raw_guard) };
            unlock_tree(*guard);
            // let tree = frrutil::validate_p(tree);
            // $native_func(tree)
        }
    };
}

// ---------------
// General Utility
// ---------------

pub fn frr_register_thread(_name: &str) {
    // This is required to allow FRR zlog to work from inside external pthreads
    unsafe { c_shim::rcu_thread_start(c_shim::rcu_thread_new(std::ptr::null_mut())) };
}

pub fn spawn<F, T>(name: &str, f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T,
    F: Send + 'static,
    T: Send + 'static,
{
    let capture_name = String::from(name);

    std::thread::Builder::new()
        .spawn(move || {
            frr_register_thread(&capture_name);
            f()
        })
        .expect("failed to spawn thread")
}

// -------
// Logging
// -------

#[macro_export]
macro_rules! zlog {
    ($level:expr, $fmt:tt, $($args:tt)*) => {{
        c_shim::ezlog($level, $fmt.as_ptr(), $($args)*);
    }};

    ($level:expr, $fmt:tt) => {{
        c_shim::ezlog($level, $fmt.as_ptr());
    }}
}

#[macro_export]
macro_rules! zlog_debug {
    ($($args:tt)*) => {
        zlog!(c_shim::LOG_DEBUG as i32, $($args)*)
    }
}

#[macro_export]
macro_rules! zlog_info {
    ($($args:tt)*) => {
        zlog!(c_shim::LOG_INFO as i32, $($args)*)
    }
}

#[macro_export]
macro_rules! zlog_warn {
    ($($args:tt)*) => {
        zlog!(c_shim::LOG_WARNING as i32, $($args)*)
    }
}

#[macro_export]
macro_rules! zlog_err {
    ($($args:tt)*) => {
        zlog!(c_shim::LOG_ERR as i32, $($args)*)
    }
}

pub struct ZlogDebug;

pub struct ZlogInfo;
pub struct ZlogWarn;
pub struct ZlogErr;

macro_rules! zlog_writer {
    ($name:tt, $level:expr) => {
        impl Write for $name {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let len = buf.len() as c_int;
                let ptr = buf.as_ptr() as *const c_char;
                // We say len - 1 to eliminate the layer::fmt() added newline
                unsafe { zlog!($level as i32, c"%.*s", len - 1, ptr) };
                Ok(len as usize)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                unsafe { c_shim::zlog_tls_buffer_flush() };
                Ok(())
            }
        }
    };
}

zlog_writer!(ZlogDebug, c_shim::LOG_DEBUG);
zlog_writer!(ZlogInfo, c_shim::LOG_INFO);
zlog_writer!(ZlogWarn, c_shim::LOG_WARNING);
zlog_writer!(ZlogErr, c_shim::LOG_ERR);

use tracing::metadata::Metadata;
use tracing::Level;
use tracing_subscriber::layer::{Context, Filter};

pub struct DebugOnlyFilter;
impl<S> Filter<S> for DebugOnlyFilter {
    fn enabled(&self, meta: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        meta.level() == &Level::DEBUG
    }
}

pub struct InfoOnlyFilter;
impl<S> Filter<S> for InfoOnlyFilter {
    fn enabled(&self, meta: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        meta.level() == &Level::INFO
    }
}

pub struct WarnOnlyFilter;
impl<S> Filter<S> for WarnOnlyFilter {
    fn enabled(&self, meta: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        meta.level() == &Level::WARN
    }
}
pub struct ErrorOnlyFilter;
impl<S> Filter<S> for ErrorOnlyFilter {
    fn enabled(&self, meta: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        meta.level() == &Level::ERROR
    }
}

///
/// Setup logging including bridging to FRR zlog
#[no_mangle]
pub extern "C" fn bridge_rust_logging() {
    /*
     * Enable some logging
     */

    // These are some custom filter examples
    // let debug_filter = FilterFn::new(|metadata| *metadata.level() == tracing::Level::DEBUG);
    // let info_filter = FilterFn::new(|metadata| *metadata.level() == tracing::Level::INFO);
    // let warn_filter = FilterFn::new(|metadata| *metadata.level() == tracing::Level::WARN);
    // let error_filter = FilterFn::new(|metadata| *metadata.level() == tracing::Level::ERROR);

    let subscriber = tracing_subscriber::registry()
        // Uncomment this to pretty print log messages to the stdout
        .with(
            fmt::layer()
                .compact()
                .with_ansi(true)
                .with_filter(tracing::level_filters::LevelFilter::TRACE)
        )
        .with(
            fmt::layer()
                .with_writer(|| -> Box<dyn std::io::Write> { Box::new(ZlogDebug {}) })
                .with_ansi(false)
                .with_target(false)
                .without_time()
                .with_filter(DebugOnlyFilter),
        )
        .with(
            fmt::layer()
                .with_writer(|| -> Box<dyn std::io::Write> { Box::new(ZlogInfo {}) })
                .with_ansi(false)
                .with_target(false)
                .without_time()
                .with_filter(InfoOnlyFilter),
        )
        .with(
            fmt::layer()
                .with_writer(|| -> Box<dyn std::io::Write> { Box::new(ZlogWarn {}) })
                .with_ansi(false)
                .with_target(false)
                .without_time()
                .with_filter(WarnOnlyFilter),
        )
        .with(
            fmt::layer()
                .with_writer(|| -> Box<dyn std::io::Write> { Box::new(ZlogErr {}) })
                .with_ansi(false)
                .with_target(false)
                .without_time()
                .with_filter(ErrorOnlyFilter),
        );

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}
