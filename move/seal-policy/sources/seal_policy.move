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
    let sig = x"0ac008b425fa03a70a065e533d0d5f4a08bd5eaa636d3952ee9d7563921aa6909a129f8f1f6cc9db3720413eddfe0958b7f8805bf97383cc31e1ff333d922a04";
    let eph_pk = x"b719205049fee26bb6f76be72c5467f9927108ad992cc163a35885ac86868b80";
    let signing_payload = x"70c7c98ee5d7db73a54afad8549f09e0858463a440a367ac88ab8f85aaa55ee3";
    assert!(ed25519::ed25519_verify(&sig, &eph_pk, &signing_payload), ENoAccess);
}