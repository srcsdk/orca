## logma

centralized log collection and normalization. tails multiple log files, normalizes timestamps, extracts severity, and combines into a single stream.

### usage

```
./logma.sh -f /var/log/syslog -f /var/log/auth.log     # monitor specific files
./logma.sh -d /var/log/ -n                               # normalize all logs in dir

python3 logma.py -f /var/log/syslog -f /var/log/auth.log  # collect and normalize
python3 logma.py -d /var/log/ --tail                       # tail directory
python3 logma.py -f syslog -o normalized.json              # json output to file
python3 logma.py -f syslog --text                          # human-readable output
```

### features

- syslog, apache, nginx, json log format parsing
- automatic timestamp normalization to iso format
- severity extraction (critical, error, warning, info, debug)
- real-time tailing with file rotation detection
- json and text output modes
- per-source statistics
