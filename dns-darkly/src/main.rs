use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use std::collections::HashMap;
use base64::{decode};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use std::env;


#[tokio::main]
async fn main() {
    let passkey = match env::var_os("DARKLY_PASSKEY") {
        Some(value) => value.into_string().unwrap(),
        None => panic!("$DARKLY_PASSKEY is not set")
    };

    query("flags.xtenduke.com".to_string(), passkey).await.err();
}

async fn query(domain: String, passkey: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut flags: HashMap<String, String> = HashMap::new();

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default()
    ).unwrap();
    let response = resolver.txt_lookup(domain).await;

    match response {
        Err(_) => println!("Empty"),
        Ok(response) => {
            let mut i = 1;
            for record in response.iter() {
                i = i + 1;
                let decrypted = decrypt_string(record.to_string(), passkey.clone()).unwrap();
                let decoded = decode_record(decrypted).unwrap();
                println!("Decoded flag - key: {} value: {}", decoded.0, decoded.1);

                flags.insert(decoded.0, decoded.1);
            }
        }
    }

    Ok(())
}

fn decrypt_string(encrypted: String, passkey: String) -> Option<String> {
    let magic_crypt = new_magic_crypt!(passkey, 256);
    let decrypted = magic_crypt.decrypt_base64_to_string(encrypted).unwrap();
    return Some(decrypted);
}

fn decode_record(record: String) -> Option<(String, String)> {
    let split: Vec<&str> = record.split("|").collect();

    assert_eq!(split.len(), 2);

    if split.len() != 2 {
        return None;
    }

    let key = String::from_utf8(decode(split[0]).unwrap()).unwrap();
    let value = String::from_utf8(decode(split[1]).unwrap()).unwrap();

    return Some((
        key,
        value 
    ));
}