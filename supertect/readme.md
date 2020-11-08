## supertect

event correlation and alert engine. scans multiple log files for attack patterns with time-window correlation and severity classification.

### usage

```
./supertect.sh -f /var/log/auth.log -f /var/log/syslog   # scan multiple logs
./supertect.sh -f auth.log -w 600 -r rules.txt           # custom window and rules

python3 supertect.py -f auth.log -f syslog               # multi-file correlation
python3 supertect.py -f auth.log -r sigma_rules/ --json   # sigma rules with json
python3 supertect.py -f auth.log --tail                    # real-time monitoring
python3 supertect.py -f auth.log -o report.json            # save report
```

### features

- multi-source event correlation
- sigma-compatible rule format (yaml)
- time-window analysis with configurable windows
- severity scoring (critical, high, medium, low)
- cross-source pattern correlation
- alert deduplication with configurable windows
- brute force and privilege escalation detection
