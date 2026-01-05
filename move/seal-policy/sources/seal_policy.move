// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module seal_policy_example::seal_policy {
    use enclave::enclave::{Enclave, create_intent_message};
    use seal_policy_example::weather::WEATHER;
    use sui::{bcs, ed25519, hash::blake2b256};

    const ENoAccess: u64 = 0;
    const WalletPKIntent: u8 = 1;

    public struct WalletPK has drop {
        pk: vector<u8>,
    }

    /// Seal approve policy that checks: 
    /// 1) Tje ID used to derive Seal key is always [0]. 
    /// 2) The sender matches the wallet PK hash. 
    /// 3) The signature is verified against the enclave's registered ephemeral pk and its payload 
    /// (the bcs bytes of the intent message of the wallet PK and the timestamp).
    /// 
    /// In this example policy, whether the enclave is the latest version is not checked. One can 
    /// pass EnclaveConfig as an argument and check config_version if needed. In addition, the 
    /// timestamp is not checked, since it's already checked at Seal session key. One may add 
    /// additional checks against the clock object. 
    entry fun seal_approve(
        id: vector<u8>,
        signature: vector<u8>,
        wallet_pk: vector<u8>,
        timestamp: u64,
        enclave: &Enclave<WEATHER>,
        ctx: &TxContext,
    ) {       
        assert!(id == vector[0u8], ENoAccess);
        assert!(ctx.sender().to_bytes() == pk_to_address(&wallet_pk), ENoAccess);

        let signing_payload = create_intent_message(
            WalletPKIntent,
            timestamp,
            WalletPK {
                pk: wallet_pk,
            },
        );
        let payload = bcs::to_bytes(&signing_payload);
        assert!(ed25519::ed25519_verify(&signature, enclave.pk(), &payload), ENoAccess);
    }

    /// Helper function to check the address derived from a public key. Assume ed25519 flag for 
    /// enclave's ephemeral key and a Sui address is derived as blake2b_hash(flag || pk).
    fun pk_to_address(pk: &vector<u8>): vector<u8> {
        let mut arr = vector[0u8];
        arr.append(*pk);
        let hash = blake2b256(&arr);
        hash
    }

    #[test]
    fun test_pk_to_address() {
        let eph_pk = x"5c38d3668c45ff891766ee99bd3522ae48d9771dc77e8a6ac9f0bde6c3a2ca48";
        let expected_bytes = x"29287d8584fb5b71b8d62e7224b867207d205fb61d42b7cce0deef95bf4e8202";
        assert!(pk_to_address(&eph_pk) == expected_bytes, ENoAccess);
    }

    #[test]
    fun test_serde() {
        // A consistency test for intent message serialization with Rust, using test data by running 
        // Nautilus server locally logged timestamp, wallet pk and serialized signing bytes. 
        let intent_msg = create_intent_message(
            WalletPKIntent,
            1767627884584,
            WalletPK {
                pk: x"b8b91c7c3afff7e75e44ce64c11455e60989697a37d16421d727e4d01607cfda",
            },
        );
        let signing_payload = bcs::to_bytes(&intent_msg);
        let expected =
            x"012808d58e9b01000020b8b91c7c3afff7e75e44ce64c11455e60989697a37d16421d727e4d01607cfda";
        assert!(signing_payload == expected);
    }
}
