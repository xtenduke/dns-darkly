use base64::encode;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use std::env;

fn main() {
    let passkey = match env::var_os("DARKLY_PASSKEY") {
        Some(value) => value.into_string().unwrap(),
        None => panic!("$DARKLY_PASSKEY is not set")
    };

    println!("Creating an encrypted key-value pair");
    println!("Enter the key:");
    let key = read();

    println!("Enter the value:");
    let value = read();

    encode_record(key, value, passkey);
}

fn read() -> String {
    let mut value = String::new();
    std::io::stdin().read_line(&mut value).unwrap();
    if value.ends_with('\n') {
        value = value.trim_end().to_string();
    }

    return value;
}

// encode as base64
// encrypt with AES
fn encode_record(
    key: String,
    value: String,
    passkey: String
) -> String {
    println!("key: {} value: {}", key, value);
    let encoded_key = encode(key);
    let encoded_value = encode(value);
    let encoded = format!("{encoded_key}|{encoded_value}");

    let encrypted = encrypt(passkey, encoded).unwrap();
    return encrypted;
}

fn encrypt(passkey: String, value: String) -> Option<String> {
    let magic_crypt = new_magic_crypt!(passkey, 256);
    let result = magic_crypt.encrypt_str_to_base64(value);

    println!("{}", result);
    return Some(result);
}