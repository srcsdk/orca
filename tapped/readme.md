## tapped

process and system monitor. tracks new process creation, detects suspicious processes, and alerts on deleted binaries.

### usage

```
sudo ./tapped.sh                              # monitor all processes
sudo ./tapped.sh -i 2 -l proc.log             # 2s interval with logging
sudo ./tapped.sh -s suspicious.txt            # custom suspicious process list
sudo ./tapped.sh -p 1234                      # monitor specific pid
```

### options

- `-i` : check interval in seconds (default: 5)
- `-l` : log file
- `-s` : file with suspicious process names (one per line)
- `-p` : monitor a specific pid
