#![no_main]

use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, sha256d};
use libfuzzer_sys::fuzz_target;
use p2poolv2_lib::node::messages::RawMessage;

// This is a smoke test: it only checks that decoding never panics on
// arbitrary input. It does not verify that successfully-decoded messages
// contain correct or expected values (that would require a round-trip
// test using real, generated Message values as the source of truth).
fuzz_target!(|payload: Vec<u8>| {
    // Build a real, correctly-framed wire message around arbitrary,
    // fuzzer-generated payload bytes: compute the genuine checksum for
    // this payload, so the message passes RawMessage's checksum gate
    // and Message::consensus_decode actually gets exercised on the
    // fuzzed content, instead of being rejected before it's ever reached.
    let hash = sha256d::Hash::hash(&payload);
    let checksum = [hash[0], hash[1], hash[2], hash[3]];

    let mut wire_bytes = Vec::new();
    (payload.len() as u32)
        .consensus_encode(&mut wire_bytes)
        .unwrap();
    checksum.consensus_encode(&mut wire_bytes).unwrap();
    wire_bytes.extend_from_slice(&payload);

    // We don't care whether this returns Ok or a clean Err - we're only
    // checking that decoding never panics on any input.
    let _ = RawMessage::consensus_decode(&mut &wire_bytes[..]);
});
