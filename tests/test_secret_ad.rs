// Copyright (c) 2018 Mark Sinclair <mark.edward.x@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// These tests are based on Argon's test.c test suite.

extern crate argon2;
extern crate hex;

use argon2::{Config, Variant};

const SEC_1: &[u8] = b"6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037";
const SEC_2: &[u8] = b"2ec0d925358f5830caf0c1cc8a3ee58b34505759428b859c79b72415f51f9221";
const SEC_3: &[u8] = b"41c89760d85b80ba1be7e959ebd16390bfb4176db9466d70f670457ccade4ec8";

const DATA_1: &[u8] = b"associated data";
const DATA_2: &[u8] = b"2ec0d925358f5830c";
const DATA_3: &[u8] = b"summertime";

#[test]
fn test_argon2d_1() {
    hash_test(Variant::Argon2i, b"password", b"somesalt", SEC_2, DATA_3);
}

#[test]
fn test_argon2d_2() {
    hash_test(Variant::Argon2i, b"password", b"somesalt", SEC_3, DATA_2);
}

#[test]
fn test_argon2d_3() {
    hash_test(
        Variant::Argon2i,
        b"differentpassword",
        b"somesalt",
        SEC_3,
        DATA_3,
    );
}

#[test]
fn test_argon2d_4() {
    hash_test(Variant::Argon2i, b"password", b"diffsalt", SEC_1, DATA_1);
}

#[test]
fn test_argon2i_1() {
    hash_test(Variant::Argon2i, b"password", b"somesalt", SEC_1, DATA_2);
}

#[test]
fn test_argon2i_2() {
    hash_test(Variant::Argon2i, b"password", b"somesalt", SEC_1, DATA_3);
}

#[test]
fn test_argon2i_3() {
    hash_test(
        Variant::Argon2i,
        b"differentpassword",
        b"somesalt",
        SEC_2,
        DATA_1,
    );
}

#[test]
fn test_argon2i_4() {
    hash_test(Variant::Argon2i, b"password", b"diffsalt", SEC_2, DATA_2);
}

#[test]
fn test_argon2id_1() {
    hash_test(Variant::Argon2id, b"password", b"somesalt", SEC_2, DATA_3);
}

#[test]
fn test_argon2id_2() {
    hash_test(Variant::Argon2id, b"password", b"somesalt", SEC_3, DATA_1);
}

#[test]
fn test_argon2id_3() {
    hash_test(
        Variant::Argon2id,
        b"differentpassword",
        b"somesalt",
        SEC_3,
        DATA_2,
    );
}

#[test]
fn test_argon2id_4() {
    hash_test(Variant::Argon2id, b"password", b"diffsalt", SEC_3, DATA_3);
}

fn hash_test(var: Variant, pwd: &[u8], salt: &[u8], secret: &[u8], ad: &[u8]) {
    let config = Config {
        secret: secret.to_owned(),
        ad: ad.to_owned(),
        variant: var,
        ..Config::default()
    };

    let encoded = argon2::hash_encoded(pwd, salt, &config).unwrap();
    let result =
        argon2::verify_encoded(encoded.as_str(), pwd, secret.to_owned(), ad.to_owned()).unwrap();
    assert!(result);
}
