## detect

network scan detection tool. monitors traffic for port scans and syn floods.

### usage

```
sudo python detect.py                              # monitor eth0
sudo python detect.py -i wlan0 --port-threshold 15 # lower threshold
sudo python detect.py --blocklist block.sh          # export iptables rules
sudo python detect.py -o alerts.json                # save alerts
```

### options

- `-i` / `--interface`   : network interface (default: eth0)
- `--port-threshold`      : ports before alerting (default: 25)
- `--window`              : time window in seconds (default: 10)
- `-f` / `--filter`      : bpf filter expression
- `--blocklist`           : export blocklist as iptables script
- `-o` / `--output`      : save alerts to json
