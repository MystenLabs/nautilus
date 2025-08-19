// Test to verify BCS encoding matches
module app::test_bcs;

use std::bcs;

#[test]
fun test_bcs_encoding() {
    let address = @0xe72cf2f4c13c7d969777b945d289b1c56f1f040bc4a4c50bc223f99649d79fcf;
    let bcs_bytes = bcs::to_bytes(&address);
    
    // This should output the exact BCS encoding that ctx.sender() would produce
    std::debug::print(&bcs_bytes);
    
    // Expected BCS encoding (32 bytes for the address)
    let expected = x"e72cf2f4c13c7d969777b945d289b1c56f1f040bc4a4c50bc223f99649d79fcf";
    assert!(bcs_bytes == expected, 0);
}