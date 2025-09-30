// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module seal_policy_example::seal_policy {
    use enclave::enclave::Enclave;
    use seal_policy_example::weather::WEATHER;
    use sui::hash::blake2b256;

    const ENoAccess: u64 = 0;

    entry fun seal_approve(_id: vector<u8>, enclave: &Enclave<WEATHER>, ctx: &TxContext) {
        // In this example whether the enclave is the latest version is not checked. One
        // can pass EnclaveConfig as an argument and check config_version if needed.
        assert!(ctx.sender().to_bytes() == pk_to_address(enclave.pk()), ENoAccess);
    }

    fun pk_to_address(pk: &vector<u8>): vector<u8> {
        // Assume ed25519 flag for enclave's ephemeral key. Derive address as blake2b_hash(flag || pk).
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
}
