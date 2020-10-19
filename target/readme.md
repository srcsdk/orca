## target

vulnerability scanner. fingerprints services and correlates with cve database.

### usage

```
python scan.py <host>
python scan.py -p 1-1000 scanme.nmap.org
python scan.py -o report.json 192.168.1.1
```

### options

- `-p` / `--ports`   : ports to scan (comma-separated or range)
- `-t` / `--threads`  : thread count (default: 20)
- `-T` / `--timeout`  : timeout per connection (default: 3s)
- `-o` / `--output`   : save results to json
