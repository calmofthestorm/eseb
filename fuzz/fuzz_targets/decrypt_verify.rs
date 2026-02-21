#![no_main]

use libfuzzer_sys::fuzz_target;

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

    let chunk_size = 1 + (data.first().copied().unwrap_or(0) as usize % 64);
    let stream = build_record32_stream(data, chunk_size);
    let _ = eseb::symmetric_decrypt_verify(
        &key,
        &stream,
        /*compress=*/ false,
        record_reader::Format::Record32,
    );
});
