## orcasec

modular security platform for network analysis, defense, and enterprise security. includes 30+ python modules and java components for siem, auth, and data pipelines.

### install

one-click:
```
curl -fsSL https://raw.githubusercontent.com/srcsdk/cybersec/master/install.sh | sh
```

or with pip:
```
pip install orcasec
```

### usage

```python
from discovery import discover
hosts = discover("192.168.1.0/24")

from netscan import scan
results = scan("192.168.1.1", ports=range(1, 1024))
```

### cli

```
orca scan --subnet 192.168.1.0/24
orca monitor --interface eth0
orca pipeline run full_scan
orca dashboard
```

### dashboard

```
python -m dashboard.server
```

opens at http://localhost:8443 with system status, scan results, module overview, and installer page.

### java modules

enterprise security components in `java/`:

- siem: log ingestion with syslog, json, and cef parsers
- auth: ldap connector and saml assertion validator
- pipeline: data streaming and alert routing

build with maven:
```
cd java && mvn package
```

### modules

conductor, containok, denied, detect, discovery, dnsguard, downseek, flow, gnore, icu, logma, netscan, nvd, over, patch, poison, probaduce, prodsec, rec, res, sike, spider, supertect, tapped, target, tropy, vaded, watch, weewoo, zone
