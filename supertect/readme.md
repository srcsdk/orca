## supertect

event correlation and alert engine. scans multiple log files for attack patterns with time-window correlation and severity classification.

### usage

```
./supertect.sh -f /var/log/auth.log -f /var/log/syslog   # scan multiple logs
./supertect.sh -f auth.log -w 600 -r rules.txt           # custom window and rules
./supertect.sh -f auth.log -o alerts.log                  # write alerts to file
```

### options

- `-f` : log file to analyze (repeatable)
- `-w` : correlation time window in seconds (default: 300)
- `-r` : rules file with grep patterns
- `-o` : alert output file

### features

- multi-file pattern matching
- time-window correlation
- severity classification (critical, high, medium, low)
- brute force detection
- alert deduplication
