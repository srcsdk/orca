## tropy

data loss prevention and exfiltration detection. monitors outbound traffic for high-volume transfers, detects dns tunneling, and scans for encoded sensitive data patterns.

### usage

```
./tropy.sh -i eth0 -m all                  # full dlp scan
./tropy.sh -m traffic -t 500               # check volume with 500MB threshold

python3 tropy.py -m all                                    # full dlp scan
python3 tropy.py -m content -f sensitive.csv               # scan file for pii
python3 tropy.py -m volume -i eth0 --volume 500            # volume anomalies
python3 tropy.py -m processes --json                       # process audit
```

### detections

- credit card numbers (luhn validated)
- ssn patterns
- api keys and aws credentials
- private key material
- shannon entropy analysis for encrypted/encoded data
- base64 block detection
- dns tunneling indicators (label length, entropy, query rate)
- outbound traffic volume and ratio anomalies
- process command line scanning
