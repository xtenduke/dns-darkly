use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use std::collections::HashMap;
use base64::{encode, decode};

#[tokio::main]
async fn main() {
    let test_record = encode_record("ipv4".to_string(), "true".to_string());
    println!("test record: {}", test_record);

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

                let decoded = decode_record(record.to_string()).unwrap();
                print!("Decoded flag - key: {} value: {}", decoded.0, decoded.1);

                flags.insert(decoded.0, decoded.1);
            }
        }
    }

    Ok(())
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

fn encode_record(key: String, value: String) -> String {
    let encoded_key = encode(key);
    let encoded_value = encode(value);
    let encoded = format!("{encoded_key}|{encoded_value}");
    return encoded;
}

// async fn request() -> Result<(), Box<dyn std::error::Error>> {
//     let resp = reqwest::get("https://httpbin.org/ip")
//         .await?
//         .json::<HashMap<String, String>>()
//         .await?;
//     println!("{:#?}", resp);
//     Ok(())
// }