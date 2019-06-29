## vaded

process evasion technique demonstrator for testing detection tools. educational tool for validating that monitoring (tapped) catches evasion attempts.

### usage

```
./vaded.sh -m rename -n sshd       # rename current process
./vaded.sh -m preload              # show ld_preload concepts
./vaded.sh -m hide                 # overview of hiding techniques
./vaded.sh -m test                 # run detection test suite
```

### options

- `-m` : mode (rename, preload, hide, test)
- `-p` : target pid (rename mode, own processes only)
- `-n` : new name for rename mode

### safety

only operates on own processes. rename mode checks uid before modifying. no actual malicious payloads are executed.
