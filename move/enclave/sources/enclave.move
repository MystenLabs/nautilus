// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Permissionless registration of an enclave.

module enclave::enclave;

use std::bcs;
use std::string::String;
use sui::ed25519;
use sui::nitro_attestation::NitroAttestationDocument;

use fun to_pcrs as NitroAttestationDocument.to_pcrs;

const EInvalidPCRs: u64 = 0;
const EInvalidConfigVersion: u64 = 1;
const EInvalidCap: u64 = 2;
const EInvalidOwner: u64 = 3;

// PCR0: Enclave image file
// PCR1: Enclave Kernel
// PCR2: Enclave application
public struct Pcrs(vector<u8>, vector<u8>, vector<u8>) has copy, drop, store;

// The expected PCRs.
// - We only define the first 3 PCRs. One can define other
//   PCRs and/or fields (e.g. user_data) if necessary as part
//   of the config.
// - See https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where
//   for more information on PCRs.
public struct EnclaveConfig<phantom T> has key {
    id: UID,
    name: String,
    pcrs: Pcrs,
    capability_id: ID,
    version: u64, // Incremented when pcrs change. 
}

// A verified enclave instance, with its public key.
public struct Enclave<phantom T> has key {
    id: UID,
    pk: vector<u8>,
    config_version: u64, // Points to the EnclaveConfig's version.
    owner: address,
}

// A capability to update the enclave config.
public struct Cap<phantom T> has key, store {
    id: UID,
}

// An intent message, used for wrapping enclave messages.
public struct IntentMessage<T: drop> has copy, drop {
    intent: u8,
    timestamp_ms: u64,
    payload: T,
}

/// Create a new `Cap` using a `witness` T from a module.
public fun new_cap<T: drop>(_: T, ctx: &mut TxContext): Cap<T> {
    Cap {
        id: object::new(ctx),
    }
}

public fun create_enclave_config<T: drop>(
    cap: &Cap<T>,
    name: String,
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
    ctx: &mut TxContext,
) {
    let enclave_config = EnclaveConfig<T> {
        id: object::new(ctx),
        name,
        pcrs: Pcrs(pcr0, pcr1, pcr2),
        capability_id: cap.id.to_inner(),
        version: 0,
    };

    transfer::share_object(enclave_config);
}

public fun register_enclave<T>(
    enclave_config: &EnclaveConfig<T>,
    document: NitroAttestationDocument,
    ctx: &mut TxContext,
) {
    let pk = enclave_config.load_pk(&document);

    let enclave = Enclave<T> {
        id: object::new(ctx),
        pk,
        config_version: enclave_config.version,
        owner: ctx.sender(),
    };

    transfer::share_object(enclave);
}

public fun verify_signature<T, P: drop>(
    enclave: &Enclave<T>,
    intent_scope: u8,
    timestamp_ms: u64,
    payload: P,
    signature: &vector<u8>,
): bool {
    let intent_message = create_intent_message(intent_scope, timestamp_ms, payload);
    let payload = bcs::to_bytes(&intent_message);
    return ed25519::ed25519_verify(signature, &enclave.pk, &payload)
}

public fun update_pcrs<T: drop>(
    config: &mut EnclaveConfig<T>,
    cap: &Cap<T>,
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
) {
    cap.assert_is_valid_for_config(config);
    config.pcrs = Pcrs(pcr0, pcr1, pcr2);
    config.version = config.version + 1;
}

public fun update_name<T: drop>(config: &mut EnclaveConfig<T>, cap: &Cap<T>, name: String) {
    cap.assert_is_valid_for_config(config);
    config.name = name;
}

public fun pcr0<T>(config: &EnclaveConfig<T>): &vector<u8> {
    &config.pcrs.0
}

public fun pcr1<T>(config: &EnclaveConfig<T>): &vector<u8> {
    &config.pcrs.1
}

public fun pcr2<T>(config: &EnclaveConfig<T>): &vector<u8> {
    &config.pcrs.2
}

public fun pk<T>(enclave: &Enclave<T>): &vector<u8> {
    &enclave.pk
}

public fun destroy_old_enclave<T>(e: Enclave<T>, config: &EnclaveConfig<T>) {
    assert!(e.config_version < config.version, EInvalidConfigVersion);
    let Enclave { id, .. } = e;
    id.delete();
}

public fun deploy_old_enclave_by_owner<T>(e: Enclave<T>, ctx: &mut TxContext) {
    assert!(e.owner == ctx.sender(), EInvalidOwner);
    let Enclave { id, .. } = e;
    id.delete();
}

public fun id<T>(enclave: &Enclave<T>): vector<u8> {
    enclave.id.to_bytes()
}

fun assert_is_valid_for_config<T>(cap: &Cap<T>, enclave_config: &EnclaveConfig<T>) {
    assert!(cap.id.to_inner() == enclave_config.capability_id, EInvalidCap);
}

fun load_pk<T>(enclave_config: &EnclaveConfig<T>, document: &NitroAttestationDocument): vector<u8> {
    assert!(document.to_pcrs() == enclave_config.pcrs, EInvalidPCRs);

    (*document.public_key()).destroy_some()
}

fun to_pcrs(document: &NitroAttestationDocument): Pcrs {
    let pcrs = document.pcrs();
    Pcrs(*pcrs[0].value(), *pcrs[1].value(), *pcrs[2].value())
}

public fun create_intent_message<P: drop>(intent: u8, timestamp_ms: u64, payload: P): IntentMessage<P> {
    IntentMessage {
        intent,
        timestamp_ms,
        payload,
    }
}

#[test_only]
public fun destroy<T>(enclave: Enclave<T>) {
    let Enclave { id, .. } = enclave;
    id.delete();
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
    let signing_payload = create_intent_message(
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
