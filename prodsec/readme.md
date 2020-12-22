## prodsec

production server hardening checks based on cis benchmarks. audits ssh configuration, file permissions, services, and password policy.

### usage

```
./prodsec.sh -m all                    # full audit
./prodsec.sh -m ssh                    # ssh config checks

python3 prodsec.py -m all                              # full cis audit
python3 prodsec.py -m ssh --json                       # ssh checks json
python3 prodsec.py --save-baseline baseline.json       # save baseline
python3 prodsec.py --baseline baseline.json            # detect drift
python3 prodsec.py -m privesc                          # privilege escalation paths
```

### checks

- ssh hardening (12 cis checks: root login, protocol, auth, banners)
- file permissions (passwd, shadow, world-writable, suid)
- service audit (telnet, rsh, cups, avahi, rpcbind)
- firewall status (ufw, firewalld, iptables)
- password policy (max age, min length, empty passwords)
- uid 0 accounts
- privilege escalation paths (sudoers nopasswd, writable PATH)
- configuration drift detection against saved baseline
