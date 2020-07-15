## watch

arp spoofing detection and network monitoring.

### usage

```
python watch.py                              # monitor arp table
python watch.py --save-baseline baseline.json # save current state
python watch.py -b baseline.json             # monitor against baseline
python watch.py --show                       # show arp table
```

### options

- `-i` / `--interface`  : network interface (default: eth0)
- `--interval`           : check interval in seconds (default: 5)
- `-b` / `--baseline`   : baseline file to compare against
- `--save-baseline`      : save current arp table as baseline
- `--show`               : display current arp table and exit
- `-o` / `--output`     : save alerts to json
