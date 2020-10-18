## downseek

tls configuration hardening auditor. checks nginx/apache configs for weak ciphers, tests protocol versions, and monitors certificate expiry.

### usage

```
./downseek.sh -c /etc/nginx/nginx.conf           # audit config file
./downseek.sh -t example.com -m proto             # test protocol versions
./downseek.sh -t example.com -m ciphers           # check cipher suite

python3 downseek.py -c nginx.conf                 # audit config
python3 downseek.py -t example.com                # scan remote host
python3 downseek.py -t example.com --mozilla      # mozilla compliance
python3 downseek.py -t example.com --json         # json output
```

### python options

- `-t` : target host
- `-p` : port (default: 443)
- `-c` : config file to audit
- `--mozilla` : check mozilla modern compatibility
- `--json` : json output with scoring

### checks

- weak cipher detection (rc4, des, null, export)
- protocol version testing (sslv2/v3, tls 1.0/1.1/1.2/1.3)
- cipher suite scoring and grading (a+ through f)
- certificate expiry and chain validation
- mozilla modern compatibility
- hsts and ocsp stapling
