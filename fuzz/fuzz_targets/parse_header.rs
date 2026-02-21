#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    const MAX_INPUT: usize = 256 * 1024;
    if data.len() > MAX_INPUT {
        return;
    }

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = eseb::parse_header(s, "eseb0::fuzz::");
        let _ = eseb::crc_decode(s, "eseb0::fuzz::");
    }
});
