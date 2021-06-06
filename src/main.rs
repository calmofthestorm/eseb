use std::convert::TryInto;
use std::io::{BufRead, Read, Write};

mod keys;

use anyhow::{Context, Error, Result};
use clap::App;
use keys::{KeyMaterial, SymmetricKey};
use sodiumoxide::crypto::secretstream;

fn fmain() -> Result<()> {
    sodiumoxide::init().map_err(|_| Error::msg("failed to init sodiumoxide"))?;

    let matches = App::new("eseb")
        .about("Elixir's Simple Encoder Binary (simple wrapper around nacl).")
        .subcommand(
            App::new("encrypt")
                .about("Encrypt and sign")
                .arg_from_usage("-e, --symmetric=<KEY> 'Symmetric encryption using key/keyfile.'"),
        )
        .subcommand(
            App::new("decrypt")
                .about("Decrypt and verify")
                .arg_from_usage("-e, --symmetric=<KEY> 'Symmetric decryption using key/keyfile.'"),
        )
        .subcommand(App::new("keygen").about("Decrypt/verify"))
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("encrypt") {
        let key = load_key(matches.value_of("symmetric").expect("validate flags"))?;

        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();

        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();

        let (mut stream, header) = secretstream::xchacha20poly1305::Stream::init_push(key.as_ref())
            .map_err(|_| Error::msg("init_push secret stream"))?;

        write_record(&mut stdout, header.as_ref()).context("write header to stdout")?;

        loop {
            let data = stdin.fill_buf().context("read cleartext from stdin")?;
            let n = data.len();

            if n == 0 {
                break;
            }

            let message = stream
                .push(data, None, secretstream::Tag::Push)
                .map_err(|_| Error::msg("secret stream push"))?;
            write_record(&mut stdout, &message).context("write crypttext to stdout")?;

            stdin.consume(n);
        }
    } else if let Some(matches) = matches.subcommand_matches("decrypt") {
        let key = load_key(matches.value_of("symmetric").expect("validate flags"))?;

        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();

        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();

        let mut buf = Vec::default();
        read_record(&mut stdin, &mut buf).context("read header from stdin")?;

        let header = secretstream::xchacha20poly1305::Header::from_slice(&buf)
            .ok_or_else(|| Error::msg("parse encryption header"))?;

        let mut stream = secretstream::xchacha20poly1305::Stream::init_pull(&header, key.as_ref())
            .map_err(|_| Error::msg("init_pull secret stream"))?;

        loop {
            buf.clear();
            read_record(&mut stdin, &mut buf).context("read record")?;

            let (message, _tag) = stream
                .pull(&buf, None)
                .map_err(|_| Error::msg("secret stream pull"))?;
            stdout
                .write_all(&message)
                .context("write crypttext to stdout")?;
        }
    } else if let Some(..) = matches.subcommand_matches("keygen") {
        let key = SymmetricKey::gen_key();
        println!("{}", &key.serialize_to_string());
    }

    Ok(())
}

fn load_key(source: &str) -> Result<SymmetricKey> {
    source
        .parse::<SymmetricKey>()
        .or_else(|_| std::fs::read_to_string(source)?.parse::<SymmetricKey>())
}

fn write_record(stdout: &mut std::io::StdoutLock, record: &[u8]) -> anyhow::Result<()> {
    let len: u32 = record.len() as u32;
    stdout
        .write_all(&len.to_be_bytes())
        .context("record length")?;
    stdout.write_all(record).context("record")
}

fn read_record(stdin: &mut std::io::StdinLock, dest: &mut Vec<u8>) -> anyhow::Result<()> {
    dest.resize(4, 0);
    let n = stdin.read(&mut dest[..1]).context("read record length")?;
    if n == 0 {
        dest.clear();
        return Ok(());
    } else {
        stdin
            .read_exact(&mut dest[1..])
            .context("read record length")?;
    }
    let len = u32::from_be_bytes(dest[..4].try_into().unwrap());
    dest.resize(len as usize, 0);
    stdin.read_exact(dest).context("read record")
}

fn main() {
    if let Err(e) = fmain() {
        eprintln!("{}", &e);
        std::process::exit(-1);
    }
}
