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
    let sig = x"bde3f4b7d5c2209b1aa84024798b6c478fa4887fa76024c3ceebb64f327c2d357a8bb3c2fec4527d969af2c419e7179807f016d74200e6087579f2d412364400";
    let eph_pk = x"4353fe686284143eb1752e8b78e92951998004b3945ae12829489978b03ac103";
    let address = sui::address::from_bytes(x"e72cf2f4c13c7d969777b945d289b1c56f1f040bc4a4c50bc223f99649d79fcf");
    let signing_payload = bcs::to_bytes(&address);
    
    // Debug: print the BCS bytes to verify encoding
    std::debug::print(&signing_payload);
    
    assert!(ed25519::ed25519_verify(&sig, &eph_pk, &signing_payload), ENoAccess);
}

#[test]
fun test_bcs_encoding_direct() {
    let address = @0xe72cf2f4c13c7d969777b945d289b1c56f1f040bc4a4c50bc223f99649d79fcf;
    let signing_payload = bcs::to_bytes(&address);
    
    // This should be exactly 32 bytes (the address itself)
    std::debug::print(&signing_payload);
    assert!(signing_payload == x"e72cf2f4c13c7d969777b945d289b1c56f1f040bc4a4c50bc223f99649d79fcf", 0);
}