## flow

network traffic flow analysis. aggregates packets into flows and tracks conversations.

### usage

```
sudo python flow.py                         # monitor eth0
sudo python flow.py -i wlan0 -f "port 80"   # filter http
sudo python flow.py --timeout 60 -o flows.json
```

### options

- `-i` / `--interface` : capture interface (default: eth0)
- `-f` / `--filter`    : bpf filter expression
- `--timeout`           : flow timeout in seconds (default: 30)
- `-o` / `--output`    : save flow data to json
