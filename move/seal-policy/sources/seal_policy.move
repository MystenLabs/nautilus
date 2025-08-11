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