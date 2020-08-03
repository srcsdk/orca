## zone

dns reconnaissance tool. enumerates records, attempts zone transfers, brute forces subdomains.

### usage

```
python dns.py example.com
python dns.py --axfr --whois example.com
python dns.py -w subdomains.txt -t 50 example.com
python dns.py -s 8.8.8.8 -o results.json example.com
```

### options

- `-s` / `--server`   : dns server to query
- `-w` / `--wordlist`  : subdomain wordlist file
- `-t` / `--threads`   : threads for brute force (default: 20)
- `--axfr`              : attempt zone transfer on all nameservers
- `--whois`             : include whois lookup
- `-o` / `--output`    : save results to json
