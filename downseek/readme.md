## downseek

tls configuration hardening auditor. checks nginx/apache configs for weak ciphers, tests protocol versions, and monitors certificate expiry.

### usage

```
./downseek.sh -c /etc/nginx/nginx.conf           # audit config file
./downseek.sh -t example.com -m proto             # test protocol versions
./downseek.sh -t example.com -m ciphers           # check cipher suite
./downseek.sh -t example.com -c nginx.conf -m all # full audit
```

### options

- `-t` : target host for remote testing
- `-m` : mode (config, proto, ciphers, all)
- `-c` : path to web server config file

### checks

- weak cipher detection (rc4, des, null, export)
- protocol version testing (sslv2/v3, tls 1.0/1.1)
- server cipher preference
- ocsp stapling
- hsts headers
- certificate expiry monitoring
