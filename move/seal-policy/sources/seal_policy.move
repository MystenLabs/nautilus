// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module app::seal_policy;

use enclave::enclave::Enclave;
use std::bcs;
use sui::ed25519;

const ENoAccess: u64 = 0;

entry fun seal_approve<T: drop>(_id: vector<u8>, enclave: &Enclave<T>, signature: vector<u8>, ctx: &TxContext) {
    let payload = bcs::to_bytes(&ctx.sender());
    assert!(ed25519::ed25519_verify(&signature, enclave.pk(), &payload), ENoAccess);
}

#[test]
fun test_seal_approve() {
    let sig = x"be1f1ac696a76b798b57e05a379cb6214b9604d2c382e542fb7cab9bfd7cfb9be4db8a8510a340a4037c38c40d6f2bdacfe6cd5fc34cd1e8d75390f0d219da00";
    let eph_pk = x"4292c5545bb6b321340100102f6cd116728b7605a5dcb3490e5f2ddf406a362e";
    let address = sui::address::from_bytes(x"e5556f937d08f31eee769cd256a3167a3c03bef7566735e7337488b4de5f39e9");
    let signing_payload = bcs::to_bytes(&address);
    assert!(ed25519::ed25519_verify(&sig, &eph_pk, &signing_payload), ENoAccess);
}