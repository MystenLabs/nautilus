// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module app::seal_policy;

use enclave::enclave::Enclave;
use sui::hash::blake2b256;

const ENoAccess: u64 = 0;

entry fun seal_approve<T: drop>(_id: vector<u8>, enclave: &Enclave<T>, ctx: &TxContext) {
    assert!(ctx.sender().to_bytes() == pk_to_address(enclave.pk()), ENoAccess);
}

fun pk_to_address(pk: &vector<u8>): vector<u8> {
    let mut arr = vector[0u8]; // assume ed25519 flag
    arr.append(*pk);
    let hash = blake2b256(&arr);
    hash
}

#[test]
fun test_pk_to_address() {
    let eph_pk = x"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let expected_bytes = x"6be28da56fc140d3d55d93a0a4805cab056bdf76eb9c8ef3d9746cbba827139e";
    assert!(pk_to_address(&eph_pk) == expected_bytes, ENoAccess);
}