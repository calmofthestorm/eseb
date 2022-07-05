use eseb::*;

use anyhow::{Error, Result};
use clap::App;

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
        crate::symmetric_encrypt_sign_file(
            &key,
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
        )?;
    } else if let Some(matches) = matches.subcommand_matches("decrypt") {
        let key = load_key(matches.value_of("symmetric").expect("validate flags"))?;
        crate::symmetric_decrypt_verify_file(
            &key,
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
        )?;
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        if matches.is_present("snow") {
            let key = SnowKeyPair::gen_key()?;
            println!("{}", &key.serialize_to_string());
            println!("{}", &key.to_public().serialize_to_string());
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

fn main() {
    if let Err(e) = fmain() {
        eprintln!("error: {}", &e);
        std::process::exit(-1);
    }
}
