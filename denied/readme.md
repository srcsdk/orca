## denied

simple web application firewall using iptables string matching. blocks common attack patterns in http traffic.

### usage

```
sudo ./denied.sh                     # install waf rules on port 80
sudo ./denied.sh -p 8080 -l waf.log  # custom port with logging
sudo ./denied.sh -c                  # check current rules
sudo ./denied.sh -r                  # remove all waf rules
```

### options

- `-l` : log blocked requests to file
- `-p` : http port to protect (default: 80)
- `-i` : network interface
- `-r` : remove all waf rules
- `-c` : check current rules
