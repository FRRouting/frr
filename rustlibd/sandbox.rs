// -*- coding: utf-8 -*-
//
// February 26 2025, Christian Hopps <chopps@labn.net>
//
// Copyright (c) 2025, LabN Consulting, L.L.C.
//
#![allow(clippy::disallowed_names)]

// =======
// HashMap
// =======

fn test_hashmap() {
    let v: Vec<&str> = "foobar=1baz&&bf%2Clag".split('&').collect();
    let v: Vec<&str> = v.into_iter().filter(|&x| !x.is_empty()).collect();
    println!("HASHMAP: split: {:?}", v);

    let qmap: HashMap<_, _> = v
        .into_iter()
        .map(|x| x.split_once('=').unwrap_or((x, "")))
        .map(|(x, y)| (_percent_decode(x), _percent_decode(y)))
        .map(|(x, y)| (String::from(x), String::from(y)))
        .collect();
    println!("HASHMAP: qmap: {:?}", qmap);
}

fn main() {
    test_hashmap();
}
