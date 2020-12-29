## res

incident response evidence collection toolkit. gathers system info, process trees, network state, user activity, and integrity checks into timestamped evidence directories.

### usage

```
./res.sh -m all                          # full collection
./res.sh -m processes -p 1234            # targeted pid investigation

python3 res.py -m all                                  # full ir collection
python3 res.py -m processes -p 1234                    # investigate pid
python3 res.py -m contain --isolate --allow-ip 10.0.0.5  # network isolation
python3 res.py -m contain --kill-pid 1234              # stop suspicious process
python3 res.py -m timeline --json                      # generate timeline
```

### evidence collected

- system info (hostname, kernel, uptime, disk, memory, modules)
- process tree with suspicious process detection
- deleted executable detection
- network state (connections, routes, arp, firewall)
- user activity (logins, cron, ssh keys, auth logs)
- file integrity (recent changes, package verification)
- automated timeline generation from evidence
- containment actions (network isolation, process stop)
- evidence manifests and archiving
