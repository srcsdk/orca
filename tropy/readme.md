## tropy

data loss prevention and exfiltration detection. monitors outbound traffic for high-volume transfers, detects dns tunneling, and scans for encoded sensitive data patterns.

### usage

```
./tropy.sh -i eth0 -m all                  # full dlp scan
./tropy.sh -m traffic -t 500               # check volume with 500MB threshold
./tropy.sh -m dns -i wlan0                 # dns tunneling detection
./tropy.sh -m patterns -o alerts.log       # pattern scan with alert output
```

### options

- `-i` : network interface (default: eth0)
- `-m` : mode (traffic, dns, patterns, all)
- `-t` : volume threshold in MB (default: 100)
- `-o` : alert output file

### detections

- outbound traffic volume anomalies
- dns tunneling via long subdomain labels
- base64 encoded data in process arguments
- credit card number patterns in logs
