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
    let sig = x"7b461a0fa4f03dda14e2e632766ebc042b2fb7bea0f267214db5f1a1b7ca2f29c4abcec2f286020025dd9f9786f833a14d9f24fbf5e140f7c0b089a000a60b02";
    let eph_pk = x"f5d8f6eef3bbbef721c03be5805ebc21a5689875173067055a7cb6775f59303c";
    let signing_payload = x"0bd46992b855ba693673f08648770b3e98d92a076774b091baac201dc501ad7d";
    assert!(ed25519::ed25519_verify(&sig, &eph_pk, &signing_payload), ENoAccess);
}