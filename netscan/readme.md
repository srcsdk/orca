## netscan

tcp/udp port scanner with banner grabbing.

### usage

```
python portscan.py <host>
python portscan.py -T 100 -b scanme.nmap.org
python portscan.py -u -t 50 192.168.1.1
python portscan.py -o results.json 10.0.0.1 1 65535
```

### options

- `-u` / `--udp`     : udp scan (default is tcp)
- `-t` / `--threads`  : thread count (default: 100)
- `-T` / `--top`      : scan top 100 or 1000 ports
- `-b` / `--banner`   : grab service banners
- `-o` / `--output`   : save results to json
- `--timeout`          : per-port timeout (default: 1s)
