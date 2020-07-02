## poison

arp cache poisoning tool for mitm testing. requires root.

### usage

```
sudo python spoof.py <target_ip> <gateway_ip>
sudo python spoof.py -i wlan0 --interval 1 192.168.1.100 192.168.1.1
```

### options

- `-i` / `--interface` : network interface (default: eth0)
- `--interval`         : poison interval in seconds (default: 2)

ctrl+c to stop. arp tables are automatically restored on exit.
