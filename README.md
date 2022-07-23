## dns-darkly

### WIP 

Remote configuration in DNS records, inspired by CobaltStrike DNS Beacon and LaunchDarkly


#### create-record
Encodes and encrypts key value pairs into strings you can put into DNS TXT records

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
Fetches, decrypts, decodes DNS TXT records, to be used as remote configuration / feature toggling

```
dns-darkly$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/dns-darkly`
Decoded flag - key: enableipv4 value: true
```



