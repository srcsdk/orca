## containok

container and docker security scanner. audits daemon configuration, running container security posture, and dockerfiles.

### usage

```
./containok.sh -m all                         # full audit
./containok.sh -m daemon                      # check daemon config
./containok.sh -m containers                  # audit running containers
./containok.sh -m image -f Dockerfile         # lint a dockerfile
```

### options

- `-m` : mode (daemon, containers, image, all)
- `-i` : image name for inspection
- `-f` : dockerfile path for linting

### checks

- privileged container detection
- docker socket mount detection
- root user detection
- host namespace usage
- dangerous capabilities (sys_admin)
- daemon configuration (userns, icc, no-new-privileges)
- dockerfile linting (secrets, latest tags, user instruction)
