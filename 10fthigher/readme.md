## 10fthigher

dynamic firewall rule management. loads blocklists into iptables and monitors logs for failed authentication to auto-block attackers.

### usage

```
sudo ./firewall.sh -b blocklist.txt                    # load blocklist
sudo ./firewall.sh -m /var/log/auth.log -t 3           # monitor auth log
sudo ./firewall.sh -b block.txt -w whitelist.txt       # blocklist with whitelist
sudo ./firewall.sh -m /var/log/auth.log -l firewall.log # monitor with logging
```

### options

- `-b` : ip blocklist file (one ip per line)
- `-w` : whitelist file (these ips are never blocked)
- `-l` : log actions to file
- `-m` : monitor log file for failed auth attempts
- `-t` : failed attempts before blocking (default: 5)
