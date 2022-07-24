## dns-darkly


Remote configuration in DNS records, inspired by CobaltStrike DNS Beacon and LaunchDarkly.

Instead of using a service like LaunchDarkly for remote configuration, why not utilise DNS server infrastructure? Feature flags have small data requirements, so fitting them in DNS records isn't a big deal.

Defaults to using cloudflare DNS over TLS, although you could use normal DNS

#### create-record
Encodes and encrypts key value pairs into strings you can put into DNS TXT records.

Requires DARKLY_PASSKEY env var. The records will be encrypted with AES256

```
create-record$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.01s
    Running `target/debug/create-record`
Creating an encrypted key-value pair
Enter the key:
enableipv4
Enter the value:
true
key: enableipv4 value: true
axtOs4GJ4UqeFZJdd6u8NkO12vQWaWL4WJtvXQejp44=
```

#### DNS Config
Set the value in your DNS configuration

![image](https://user-images.githubusercontent.com/5002212/180603872-fe15564c-fd76-4ed8-a926-fe8b405b2956.png)


#### dns-darkly
Fetches, decrypts, decodes DNS TXT records, to be used as remote configuration / feature toggling.

Set DARKLY_DOMAIN env var to the domain you wish to fetch records for.

You also need the same DARKLY_PASSKEY from the create-record stage


```
dns-darkly$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/dns-darkly`
Decoded flag - key: enableipv4 value: true
```



