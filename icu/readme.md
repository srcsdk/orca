## icu

packet capture and protocol analysis tool. wraps tcpdump with structured output.

### usage

```
sudo python capture.py                          # live capture on eth0
sudo python capture.py -i wlan0 -c 100          # capture 100 packets
sudo python capture.py -f "port 80" -w http.pcap # save to pcap
python capture.py -r http.pcap                   # analyze existing pcap
python capture.py -r http.pcap -o stats.json     # export stats
```

### options

- `-i` / `--interface` : capture interface (default: eth0)
- `-c` / `--count`     : packets to capture (0=unlimited)
- `-f` / `--filter`    : bpf filter expression
- `-w` / `--write`     : write pcap file
- `-r` / `--read`      : analyze existing pcap
- `-o` / `--output`    : save stats to json
