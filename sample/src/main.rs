use dns_darkly::query;
use std::env;

#[tokio::main]
async fn main() {
    let passkey = match env::var_os("DARKLY_PASSKEY") {
        Some(value) => value.into_string().unwrap(),
        None => {
            println!("default to somesecretpasskey");
            "somesecretpasskey".to_string()
        }
    };

    let domain = match env::var_os("DARKLY_DOMAIN") {
        Some(value) => value.into_string().unwrap(),
        None => {
            println!("default to flags.xtenduke.com");
            "flags.xtenduke.com".to_string()
        }
    };

    // Query DNS and get the record set for the domain
    let result = query(domain, passkey).await;
    // If it succeeded
    if let Ok(result) = result {
        // Pull the flag "enable_ipv6" out
        let res = result.boolean("enable_ipv6".to_string()).unwrap();
        if res {
            println!("enable_ipv6 was true");
        } else {
            println!("enable_ipv6 was false");
        }
    }
}
