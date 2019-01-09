## dnsguard

dns monitoring and anomaly detection. watches dns traffic for high-entropy subdomains (dga detection), excessive query rates, and dns tunneling indicators.

### usage

```
sudo ./dnsguard.sh                            # monitor eth0
sudo ./dnsguard.sh -i wlan0 -t 100            # custom interface and threshold
sudo ./dnsguard.sh -e 4.0 -l /var/log/dns.log # stricter entropy, log to file
```

### options

- `-i` : network interface (default: eth0)
- `-t` : query rate threshold per source per minute (default: 50)
- `-l` : log file path
- `-e` : entropy threshold for dga detection (default: 3.5)
