use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

use eseb::{KeyMaterial, SymmetricKey};

fn eseb_cmd() -> Command {
    let bin = assert_cmd::cargo::cargo_bin!("eseb");
    Command::new(bin)
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x: u64 = 0x9e3779b97f4a7c15;
    for byte in &mut out {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x = x.wrapping_mul(0x2545F4914F6CDD1D);
        *byte = (x & 0xff) as u8;
    }
    out
}

fn run_encrypt(cleartext: &[u8], key: &SymmetricKey, compress: bool, legacy: bool) -> Vec<u8> {
    let mut cmd = eseb_cmd();
    cmd.arg("encrypt")
        .arg("--symmetric")
        .arg(key.serialize_to_string());
    if compress {
        cmd.arg("--compress");
    }
    if legacy {
        cmd.arg("--legacy");
    }

    let output = cmd
        .write_stdin(cleartext)
        .assert()
        .success()
        .get_output()
        .clone();
    output.stdout
}

fn run_decrypt(ciphertext: &[u8], key: &SymmetricKey, compress: bool, legacy: bool) -> Vec<u8> {
    let mut cmd = eseb_cmd();
    cmd.arg("decrypt")
        .arg("--symmetric")
        .arg(key.serialize_to_string());
    if compress {
        cmd.arg("--compress");
    }
    if legacy {
        cmd.arg("--legacy");
    }

    let output = cmd
        .write_stdin(ciphertext)
        .assert()
        .success()
        .get_output()
        .clone();
    output.stdout
}

fn run_encrypt_with_key_file(
    cleartext: &[u8],
    key_file: &std::path::Path,
    compress: bool,
    legacy: bool,
) -> Vec<u8> {
    let mut cmd = eseb_cmd();
    cmd.arg("encrypt").arg("--symmetric").arg(key_file);
    if compress {
        cmd.arg("--compress");
    }
    if legacy {
        cmd.arg("--legacy");
    }

    let output = cmd
        .write_stdin(cleartext)
        .assert()
        .success()
        .get_output()
        .clone();
    output.stdout
}

fn run_decrypt_with_key_file(
    ciphertext: &[u8],
    key_file: &std::path::Path,
    compress: bool,
    legacy: bool,
) -> Vec<u8> {
    let mut cmd = eseb_cmd();
    cmd.arg("decrypt").arg("--symmetric").arg(key_file);
    if compress {
        cmd.arg("--compress");
    }
    if legacy {
        cmd.arg("--legacy");
    }

    let output = cmd
        .write_stdin(ciphertext)
        .assert()
        .success()
        .get_output()
        .clone();
    output.stdout
}

#[test]
fn test_cli_encrypt_decrypt_roundtrip_record() {
    let key = SymmetricKey::gen_key().unwrap();
    let cleartext = b"this is halloween";
    let ciphertext = run_encrypt(
        cleartext, &key, /*compress=*/ false, /*legacy=*/ false,
    );
    let decrypted = run_decrypt(
        &ciphertext,
        &key,
        /*compress=*/ false,
        /*legacy=*/ false,
    );
    assert_eq!(decrypted, cleartext);
}

#[test]
fn test_cli_encrypt_decrypt_roundtrip_record32_compress() {
    let key = SymmetricKey::gen_key().unwrap();
    let cleartext = b"pumpkins scream in the dead of night";
    let ciphertext = run_encrypt(
        cleartext, &key, /*compress=*/ true, /*legacy=*/ true,
    );
    let decrypted = run_decrypt(
        &ciphertext,
        &key,
        /*compress=*/ true,
        /*legacy=*/ true,
    );
    assert_eq!(decrypted, cleartext);
}

#[test]
fn test_cli_decrypt_with_wrong_key_fails() {
    let key1 = SymmetricKey::gen_key().unwrap();
    let key2 = SymmetricKey::gen_key().unwrap();
    let cleartext = b"wrong key should fail";
    let ciphertext = run_encrypt(
        cleartext, &key1, /*compress=*/ false, /*legacy=*/ false,
    );

    eseb_cmd()
        .arg("decrypt")
        .arg("--symmetric")
        .arg(key2.serialize_to_string())
        .write_stdin(ciphertext)
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn test_cli_encrypt_decrypt_roundtrip_record32_no_compress() {
    let key = SymmetricKey::gen_key().unwrap();
    let cleartext = b"record32 no compress";
    let ciphertext = run_encrypt(
        cleartext, &key, /*compress=*/ false, /*legacy=*/ true,
    );
    let decrypted = run_decrypt(
        &ciphertext,
        &key,
        /*compress=*/ false,
        /*legacy=*/ true,
    );
    assert_eq!(decrypted, cleartext);
}

#[test]
fn test_cli_encrypt_decrypt_roundtrip_record_compress() {
    let key = SymmetricKey::gen_key().unwrap();
    let cleartext = b"record compress";
    let ciphertext = run_encrypt(
        cleartext, &key, /*compress=*/ true, /*legacy=*/ false,
    );
    let decrypted = run_decrypt(
        &ciphertext,
        &key,
        /*compress=*/ true,
        /*legacy=*/ false,
    );
    assert_eq!(decrypted, cleartext);
}

#[test]
fn test_cli_key_file_roundtrip() {
    let key = SymmetricKey::gen_key().unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut key_file, key.serialize_to_string().as_bytes()).unwrap();

    let cleartext = b"key file roundtrip";
    let ciphertext = run_encrypt_with_key_file(
        cleartext,
        key_file.path(),
        /*compress=*/ false,
        /*legacy=*/ false,
    );
    let decrypted = run_decrypt_with_key_file(
        &ciphertext,
        key_file.path(),
        /*compress=*/ false,
        /*legacy=*/ false,
    );
    assert_eq!(decrypted, cleartext);
}

#[test]
fn test_cli_invalid_key_string_fails() {
    eseb_cmd()
        .arg("encrypt")
        .arg("--symmetric")
        .arg("not-a-key")
        .write_stdin(b"bad key")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn test_cli_missing_symmetric_flag_fails_encrypt() {
    eseb_cmd()
        .arg("encrypt")
        .write_stdin(b"missing key")
        .assert()
        .failure();
}

#[test]
fn test_cli_missing_symmetric_flag_fails_decrypt() {
    eseb_cmd()
        .arg("decrypt")
        .write_stdin(b"missing key")
        .assert()
        .failure();
}

#[test]
fn test_cli_unknown_subcommand_fails() {
    eseb_cmd().arg("unknown").assert().failure();
}

#[test]
fn test_cli_key_file_missing_fails() {
    eseb_cmd()
        .arg("encrypt")
        .arg("--symmetric")
        .arg("this-file-should-not-exist.key")
        .write_stdin(b"missing key file")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn test_cli_large_payload_record_roundtrip() {
    let key = SymmetricKey::gen_key().unwrap();
    let payload = vec![0x5a; 2 * 1024 * 1024];
    let ciphertext = run_encrypt(
        &payload, &key, /*compress=*/ false, /*legacy=*/ false,
    );
    let decrypted = run_decrypt(
        &ciphertext,
        &key,
        /*compress=*/ false,
        /*legacy=*/ false,
    );
    assert_eq!(decrypted, payload);
}

#[test]
fn test_cli_large_payload_record_compress_roundtrip() {
    let key = SymmetricKey::gen_key().unwrap();
    let payload = vec![0x7f; 2 * 1024 * 1024];
    let ciphertext = run_encrypt(
        &payload, &key, /*compress=*/ true, /*legacy=*/ false,
    );
    let decrypted = run_decrypt(
        &ciphertext,
        &key,
        /*compress=*/ true,
        /*legacy=*/ false,
    );
    assert_eq!(decrypted, payload);
}

#[test]
fn test_cli_large_high_entropy_record_roundtrip() {
    let key = SymmetricKey::gen_key().unwrap();
    let payload = deterministic_bytes(4 * 1024 * 1024);
    let ciphertext = run_encrypt(
        &payload, &key, /*compress=*/ false, /*legacy=*/ false,
    );
    let decrypted = run_decrypt(
        &ciphertext,
        &key,
        /*compress=*/ false,
        /*legacy=*/ false,
    );
    assert_eq!(decrypted, payload);
}

#[test]
fn test_cli_large_high_entropy_record32_roundtrip() {
    let key = SymmetricKey::gen_key().unwrap();
    let payload = deterministic_bytes(4 * 1024 * 1024);
    let ciphertext = run_encrypt(
        &payload, &key, /*compress=*/ false, /*legacy=*/ true,
    );
    let decrypted = run_decrypt(
        &ciphertext,
        &key,
        /*compress=*/ false,
        /*legacy=*/ true,
    );
    assert_eq!(decrypted, payload);
}
