## rec

service fingerprinting and banner grabbing tool.

### usage

```
python grab.py <host>
python grab.py -p 22,80,443,8080 scanme.nmap.org
python grab.py -p 1-1000 -o results.json 192.168.1.1
```

### options

- `-p` / `--ports`   : ports to scan (comma-separated or range, default: 21,22,25,80,443)
- `-t` / `--threads`  : thread count (default: 20)
- `-T` / `--timeout`  : timeout per connection (default: 3s)
- `-o` / `--output`   : save results to json
