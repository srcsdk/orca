## logma

centralized log collection and normalization. tails multiple log files, normalizes timestamps, extracts severity, and combines into a single stream.

### usage

```
./logma.sh -f /var/log/syslog -f /var/log/auth.log     # monitor specific files
./logma.sh -d /var/log/ -n                               # normalize all logs in dir
./logma.sh -f /var/log/syslog -o combined.log            # output to file
```

### options

- `-f` : log file to monitor (repeatable)
- `-d` : directory containing .log files
- `-o` : output file (default: stdout)
- `-n` : normalize timestamps to iso format

### features

- syslog, apache, nginx timestamp parsing
- severity extraction (critical, error, warning, info)
- real-time tailing with source tracking
- combined output stream with source labels
