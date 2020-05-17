## discovery

network host discovery tool. finds live hosts on a subnet using ping sweep.

### install

```
pip install -r requirements.txt
```

(no external dependencies - uses standard library only)

### usage

```
python scan.py 192.168.1.0/24
python scan.py -t 100 -o results.json 10.0.0.0/24
python scan.py                          # auto-detect local subnet
```

### options

- `-t` / `--threads` : number of threads (default: 50)
- `-T` / `--timeout` : ping timeout in seconds (default: 1)
- `-o` / `--output`  : save results to json file
- `-v` / `--verbose`  : verbose output

### bash version

`scan.sh` is the original bash version. `scan.py` is the python rewrite.
