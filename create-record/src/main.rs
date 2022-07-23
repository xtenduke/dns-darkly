use base64::encode;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

fn main() {
    let passkey = "somesecretpassword".to_string();

    encode_record(
        "disable_ipv6".to_string(),
        "true".to_string(),
        passkey,
    );
}

// encode as base64
// encrypt with AES
fn encode_record(
    key: String,
    value: String,
    passkey: String
) -> String {
    let encoded_key = encode(key);
    let encoded_value = encode(value);
    let encoded = format!("{encoded_key}|{encoded_value}");

    let encrypted = encrypt(passkey, encoded).unwrap();
    return encrypted;
}

fn encrypt(passkey: String, value: String) -> Option<String> {
    println!("Encrypting with key: {}, value: {}", passkey, value);
    let magic_crypt = new_magic_crypt!(passkey, 256);
    let result = magic_crypt.encrypt_str_to_base64(value);

    println!("Result: {}", result);
    return Some(result);
}