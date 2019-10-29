## prodsec

production server hardening checks based on cis benchmarks. audits ssh configuration, file permissions, services, and password policy.

### usage

```
./prodsec.sh -m all                    # full audit
./prodsec.sh -m ssh                    # ssh config checks
./prodsec.sh -m perms                  # file permission audit
./prodsec.sh -m services              # service audit
./prodsec.sh -m password -o report.txt # password policy with report
```

### options

- `-m` : mode (ssh, perms, services, password, all)
- `-o` : output report file

### checks

- ssh hardening (root login, protocol, auth methods)
- file permissions (passwd, shadow, world-writable, suid)
- risky services (telnet, rsh, cups)
- firewall status
- password policy (max age, min length, empty passwords)
- uid 0 accounts
