## dns-darkly

### WIP 

Remote configuration in DNS records, inspired by CobaltStrike DNS Beacon and LaunchDarkly


#### create-record
Encodes and encrypts key value pairs into strings you can put into DNS TXT records

```
$ cargo run
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


#### dns-darkly
Fetches, decrypts, decodes DNS TXT records, to be used as remote configuration / feature toggling
