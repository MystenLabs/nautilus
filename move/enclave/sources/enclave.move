// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Permissionless registration of an enclave.

module enclave::enclave;

use std::bcs;
use std::string::String;
use sui::ed25519;
use sui::nitro_attestation::NitroAttestationDocument;

const EInvalidWitness: u64 = 2;
const EPcrMissmatch: u64 = 3;
const ECannotBeOlder: u64 = 4;

use fun to_pcrs as NitroAttestationDocument.to_pcrs;

// The expected PCRs.
// - We only define the first 3 PCRs. One can define other
//   PCRs and/or fields (e.g. user_data) if necessary as part
//   of the config.
// - See https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where
//   for more information on PCRs.
public struct Pcrs(vector<u8>, vector<u8>, vector<u8>) has copy, drop, store;

// A verified enclave instance, with its public key.
public struct Enclave<phantom T> has key {
    id: UID,
    name: String,
    pk: vector<u8>,
    pcr: Pcrs,
    version: u64,
    latest_update_ms: u64,
}

// A capability to update the enclave config.
public struct Cap<phantom T> has key, store {
    id: UID,
    enclave_id: ID,
}

// An intent message, used for wrapping enclave messages.
public struct IntentMessage<T: drop> has copy, drop {
    intent: u8,
    timestamp_ms: u64,
    payload: T,
}

public fun new<T: drop>(witness: T, name: String, ctx: &mut TxContext): Cap<T> {
    assert!(sui::types::is_one_time_witness(&witness), EInvalidWitness);

    let enclave = Enclave<T> {
        id: object::new(ctx),
        name,
        pk: vector[],
        pcr: Pcrs(vector[], vector[], vector[]),
        version: 0,
        latest_update_ms: 0,
    };

    let cap = Cap {
        id: object::new(ctx),
        enclave_id: enclave.id.to_inner(),
    };

    transfer::share_object(enclave);
    cap
}

/// Admin's way of updating PCRs
public fun update_pcrs<T>(
    enclave: &mut Enclave<T>,
    _cap: &Cap<T>,
    document: NitroAttestationDocument,
) {
    enclave.pk = (*document.public_key()).destroy_some();
    enclave.pcr = document.to_pcrs();
    enclave.latest_update_ms = *document.timestamp();

    // bump version!
    enclave.version = enclave.version + 1;
}

/// Update public key publicly.
public fun update_pk<T>(enclave: &mut Enclave<T>, document: NitroAttestationDocument) {
    assert!(enclave.pcr == document.to_pcrs(), EPcrMissmatch);
    assert!(enclave.latest_update_ms < *document.timestamp(), ECannotBeOlder);

    enclave.pk = (*document.public_key()).destroy_some();
}

public fun verify_signature<T, P: drop>(
    enclave: &Enclave<T>,
    intent_scope: u8,
    timestamp_ms: u64,
    payload: P,
    signature: &vector<u8>,
): bool {
    let intent_message = new_intent_message(intent_scope, timestamp_ms, payload);
    let payload = bcs::to_bytes(&intent_message);
    return ed25519::ed25519_verify(signature, &enclave.pk, &payload)
}

public fun update_name<T: drop>(enclave: &mut Enclave<T>, _cap: &Cap<T>, name: String) {
    enclave.name = name;
}

public fun pcrs<T>(enclave: &Enclave<T>): (vector<u8>, vector<u8>, vector<u8>) {
    (enclave.pcr.0, enclave.pcr.1, enclave.pcr.2)
}

public fun pk<T>(enclave: &Enclave<T>): &vector<u8> {
    &enclave.pk
}

fun to_pcrs(document: &NitroAttestationDocument): Pcrs {
    let pcrs = document.pcrs();
    Pcrs(*pcrs[0].value(), *pcrs[1].value(), *pcrs[2].value())
}

fun new_intent_message<P: drop>(intent: u8, timestamp_ms: u64, payload: P): IntentMessage<P> {
    IntentMessage {
        intent,
        timestamp_ms,
        payload,
    }
}

#[test_only]
public struct SigningPayload has copy, drop {
    location: String,
    temperature: u64,
}

#[test]
fun test_serde() {
    // serialization should be consistent with rust test see `fn test_serde` in `src/nautilus-server/app.rs`.
    let scope = 0;
    let timestamp = 1744038900000;
    let signing_payload = new_intent_message(
        scope,
        timestamp,
        SigningPayload {
            location: b"San Francisco".to_string(),
            temperature: 13,
        },
    );
    let bytes = bcs::to_bytes(&signing_payload);
    assert!(bytes == x"0020b1d110960100000d53616e204672616e636973636f0d00000000000000", 0);
}
