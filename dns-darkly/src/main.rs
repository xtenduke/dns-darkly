use std::error::Error;
use std::fmt;
use magic_crypt::MagicCryptError;
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

    let domain = match env::var_os("DARKLY_DOMAIN") {
        Some(value) => value.into_string().unwrap(),
        None => panic!("$DARKLY_DOMAIN is not set")
    };

    query(domain, passkey).await.err();
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
                let decrypted = decrypt_string(record.to_string(), passkey.clone());

                if let Ok(decrypted) = decrypted {
                    let decoded = decode_record(decrypted);
                    if let Ok(decoded) = decoded {
                        println!("Decoded flag - key: {} value: {}", decoded.0, decoded.1);
                        flags.insert(decoded.0, decoded.1);
                    } else {
                        println!("Failed to decode value: {}, cause: {}", record.to_string(), decoded.err().unwrap());
                        continue;
                    }
                } else {
                    println!("Failed to decrypt value: {} cause: {}", record.to_string(), decrypted.err().unwrap());
                    continue;
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct DecodeRecordError {
    cause: String,
}

impl DecodeRecordError {
    fn new(msg: &str) -> DecodeRecordError {
        DecodeRecordError{cause: msg.to_string()}
    }
}

impl fmt::Display for DecodeRecordError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.cause)
    }
}

impl Error for DecodeRecordError {
    fn description(&self) -> &str {
        &self.cause
    }
}

fn decrypt_string(encrypted: String, passkey: String) -> Result<String, MagicCryptError> {
    let magic_crypt = new_magic_crypt!(passkey, 256);
    return magic_crypt.decrypt_base64_to_string(encrypted);
}

fn decode_record(record: String) -> Result<(String, String), DecodeRecordError> {
    let split: Vec<&str> = record.split("|").collect();

    assert_eq!(split.len(), 2);

    if split.len() != 2 {
        return Err(DecodeRecordError::new("Failed to split record"));
    }

    let key = decode_part(split[0].to_string());
    let value = decode_part(split[1].to_string());

    if let Ok(key) = key {
        if let Ok(value) = value {
            return Ok((key, value));
        } else {
            return Err(value.err().unwrap());
        }
    } else {
        return Err(key.err().unwrap());
    }
}

fn decode_part(value: String) -> Result<String, DecodeRecordError> {
    let decoded_bytes = decode(value);
    if let Ok(decoded_bytes) = decoded_bytes {
        let decoded_string = String::from_utf8(decoded_bytes);
        if let Ok(decoded_string) = decoded_string {
            return Ok(decoded_string);
        } else {
            Err(DecodeRecordError::new("Decoded record invalid utf8 string"))
        }
    } else {
        return Err(DecodeRecordError::new("Failed to decode record"));
    }
}