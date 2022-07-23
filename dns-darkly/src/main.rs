use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use std::collections::HashMap;
use base64::{decode};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};


#[tokio::main]
async fn main() {
    query("flags.xtenduke.com".to_string()).await.err();
}

async fn query(domain: String) -> Result<(), Box<dyn std::error::Error>> {
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

                let decrypted = decrypt_string(record.to_string()).unwrap();
                let decoded = decode_record(decrypted).unwrap();
                print!("Decoded flag - key: {} value: {}", decoded.0, decoded.1);

                flags.insert(decoded.0, decoded.1);
            }
        }
    }

    Ok(())
}

fn decrypt_string(encrypted: String) -> Option<String> {
    let magic_crypt = new_magic_crypt!("somesecretpassword", 256);
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