## weewoo

intrusion detection system. parses network traffic for known attack signatures including syn floods, port scans, and shellcode patterns.

### usage

```
sudo ./weewoo.sh                          # monitor eth0
sudo ./weewoo.sh -i wlan0 -l alerts.log   # custom interface with logging
sudo ./weewoo.sh -r capture.pcap          # analyze pcap file
sudo ./weewoo.sh -t 50                    # lower syn flood threshold
```

### options

- `-i` : network interface (default: eth0)
- `-r` : read from pcap file instead of live capture
- `-l` : log alerts to file
- `-t` : syn flood threshold per second (default: 100)
