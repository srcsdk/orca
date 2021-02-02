## orcasec

modular security toolkit for network analysis and defense. includes 30+ modules for discovery, scanning, monitoring, and incident response.

### install

```
pip install orcasec
```

### usage

```python
# network discovery
from discovery import discover
hosts = discover("192.168.1.0/24")

# port scanning
from netscan import scan
results = scan("192.168.1.1", ports=range(1, 1024))

# target enumeration
from target import enumerate_target
info = enumerate_target("example.com")
```

### cli

```
orcasec-discovery --subnet 192.168.1.0/24
orcasec-netscan --host 192.168.1.1 --ports 1-1024
orcasec-target --domain example.com
orcasec-spider --url https://example.com
```

### modules

conductor, containok, denied, detect, discovery, dnsguard, downseek, flow, gnore, icu, logma, netscan, nvd, over, patch, poison, probaduce, prodsec, rec, res, sike, spider, supertect, tapped, target, tropy, vaded, watch, weewoo, zone

https://github.com/srcsdk/cybersec
