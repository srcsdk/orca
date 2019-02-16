## patch

patch and configuration auditor. checks system configs against security best practices and audits package versions.

### usage

```
./audit.sh              # run all checks
./audit.sh -c           # config checks only
./audit.sh -p           # package checks only
./audit.sh -v -o report # verbose with output file
```

### options

- `-c` : check configuration files
- `-p` : check package versions
- `-o` : write report to file
- `-v` : verbose output (show passing checks)
