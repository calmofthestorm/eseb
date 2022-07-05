use std::convert::TryInto;
use std::io::{BufRead, Read, Write};

mod key_util;
mod snow_key;
mod symmetric_key;

use anyhow::{Context, Error, Result};
use clap::App;
use key_util::KeyMaterial;
use snow_key::SnowKeyPair;
use sodiumoxide::crypto::secretstream;
use symmetric_key::SymmetricKey;

include!(concat!(env!("OUT_DIR"), "/generated_stamp.rs"));

// Encrypts/decrypts messages. Does not use AES-128.

fn fmain() -> Result<()> {
    sodiumoxide::init().map_err(|_| Error::msg("failed to init sodiumoxide"))?;

    let matches = App::new("eseb")
        .name(env!("CARGO_PKG_NAME"))
        .about("Elixir's Simple Encoder Binary, a simple wrapper around NaCl to perform symmetric encryption and verification of files.")
        .version(format!("{} ({})", env!("CARGO_PKG_VERSION"), BUILD_STAMP.git_revision_cleanness()).as_ref())
        .author(env!("CARGO_PKG_AUTHORS"))
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
        .subcommand(App::new("keygen").about("Generate symmetric key")
                    .arg_from_usage("--snow 'Generate Snow keypair'")
                    .arg_from_usage("--symmetric 'Generate symmetric key'")
        )
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

        // Probably not necessary but should be sufficient.
        let message = stream
            .push(b"", None, secretstream::Tag::Message)
            .map_err(|_| Error::msg("secret stream push initial"))?;
        write_record(&mut stdout, &message).context("write initial crypttext to stdout")?;

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

        let message = stream
            .push(b"", None, secretstream::Tag::Final)
            .map_err(|_| Error::msg("secret stream push final"))?;
        write_record(&mut stdout, &message).context("write initial crypttext to stdout")?;
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

        // IDT we actually need these but it's easier this way.
        read_record(&mut stdin, &mut buf).context("read header from stdin")?;

        if stream.is_finalized() {
            return Err(Error::msg("decrypt stream finalized earlier than expected"));
        }

        let (message, tag) = stream
            .pull(&buf, None)
            .map_err(|_| Error::msg("secret stream pull"))?;

        if tag != secretstream::Tag::Message {
            return Err(Error::msg("incorrect tag"));
        }

        if !message.is_empty() {
            return Err(Error::msg("initial message not empty"));
        }

        loop {
            buf.clear();
            read_record(&mut stdin, &mut buf).context("read record")?;

            let (message, tag) = stream
                .pull(&buf, None)
                .map_err(|_| Error::msg("secret stream pull"))?;

            if stream.is_finalized() != (tag == secretstream::Tag::Final) {
                return Err(Error::msg("tag final mismatch"));
            }

            if stream.is_finalized() {
                read_record(&mut stdin, &mut buf).context("read record")?;
                if !buf.is_empty() {
                    return Err(Error::msg("data follows end of stream"));
                } else {
                    break;
                }
            }

            stdout
                .write_all(&message)
                .context("write crypttext to stdout")?;
        }
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        if matches.is_present("snow") {
            let key = SnowKeyPair::gen_key()?;
            println!("{}", &key.serialize_to_string());
            println!("{}", &key.public().serialize_to_string());
        } else {
            let key = SymmetricKey::gen_key()?;
            println!("{}", &key.serialize_to_string());
        }
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
        eprintln!("error: {}", &e);
        std::process::exit(-1);
    }
}
