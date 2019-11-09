## res

incident response evidence collection toolkit. gathers system info, process trees, network state, user activity, and integrity checks into timestamped evidence directories.

### usage

```
./res.sh -m all                          # full collection
./res.sh -m processes -p 1234            # targeted pid investigation
./res.sh -m network -o /evidence         # network evidence to custom dir
./res.sh -m users                        # user and login activity
```

### options

- `-m` : mode (collect, network, processes, users, integrity, all)
- `-o` : output directory (default: ./ir_evidence)
- `-p` : suspicious pid for detailed collection

### evidence collected

- system info (hostname, kernel, uptime, disk, memory)
- process tree with cpu/memory ranking
- network connections and listening ports
- user logins, cron jobs, ssh keys
- recently modified system files
- package integrity verification
- rootkit indicators
