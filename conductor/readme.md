## conductor

security orchestration engine that chains modules into automated workflows. supports yaml playbooks, variable substitution, and conditional step execution.

### install

```
pip install pyyaml  # optional, for yaml playbooks
```

### usage

```
python3 conductor.py list modules                               # list available modules
python3 conductor.py list playbooks                             # list builtin playbooks
python3 conductor.py run recon --var target=10.0.0.0/24         # run builtin playbook
python3 conductor.py run playbook.yml --dry-run                 # dry run yaml playbook
python3 conductor.py run incident_response --json               # json output
```

### playbook format (yaml)

```yaml
name: custom scan
description: network audit workflow
variables:
  target: 192.168.1.0/24
steps:
  - name: discover hosts
    module: netscan
    args: ["-s", "${target}"]
    on_fail: abort
  - name: port scan
    module: target
    args: ["-t", "${target}"]
    condition: prev_success
    timeout: 600
```

### options

- `run` : execute a playbook (file or builtin name)
- `list` : list modules or playbooks
- `--var` : override variable (key=value, repeatable)
- `--dry-run` : simulate without executing
- `--base` : custom module base path

### builtin playbooks

- recon: network discovery and enumeration
- incident_response: evidence collection and triage
- hardening: server hardening verification
