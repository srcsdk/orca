## containok

container and docker security scanner. audits daemon configuration, running container security posture, and dockerfiles.

### usage

```
./containok.sh -m all                         # full audit
./containok.sh -m daemon                      # check daemon config

python3 containok.py -m all                   # full audit
python3 containok.py -m dockerfile -f Dockerfile
python3 containok.py -m compose -f docker-compose.yml
python3 containok.py -m containers --json     # json output
```

### checks

- privileged container detection
- docker socket mount detection
- root user and capability analysis
- host namespace usage (pid, network, ipc)
- daemon configuration (userns, icc, no-new-privileges)
- dockerfile linting (secrets, latest tags, curl|sh, user instruction)
- docker-compose audit (secrets in env, privileged, socket mounts)
- port binding analysis
