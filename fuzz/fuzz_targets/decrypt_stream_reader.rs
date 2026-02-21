#![no_main]

use libfuzzer_sys::fuzz_target;
use record_reader::{BufferRecordReader, Format};
use std::io::Read;

fn build_record32_stream(data: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + chunk_size, data.len());
        let len = (end - offset) as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&data[offset..end]);
        offset = end;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    const MAX_INPUT: usize = 256 * 1024;
    if data.len() > MAX_INPUT {
        return;
    }

    let key = match eseb::SymmetricKey::gen_key() {
        Ok(key) => key,
        Err(_) => return,
    };

    let compress = data.first().map(|b| b & 1 == 1).unwrap_or(false);
    let chunk_size = 1 + (data.first().copied().unwrap_or(0) as usize % 64);
    let stream = build_record32_stream(data, chunk_size);

    let reader = BufferRecordReader::new(stream.into(), Format::Record32, usize::MAX);
    let mut clear_reader = match eseb::DecryptingReader::new(reader, key, compress) {
        Ok(reader) => reader,
        Err(_) => return,
    };

    let mut buf = [0u8; 64];
    loop {
        match clear_reader.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
});
