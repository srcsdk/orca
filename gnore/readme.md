## gnore

tls/ssl scanner and certificate analyzer.

### usage

```
python tls_scan.py example.com
python tls_scan.py -p 8443 --ciphers 192.168.1.1
python tls_scan.py -o report.json example.com
```

### options

- `-p` / `--port`    : port to scan (default: 443)
- `--ciphers`         : enumerate all supported cipher suites
- `-T` / `--timeout`  : connection timeout (default: 5s)
- `-o` / `--output`   : save results to json
