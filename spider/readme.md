## spider

web directory scanner. checks for common paths, sensitive files, and admin panels using curl.

### usage

```
./spider.sh -u http://target.com                    # scan common paths
./spider.sh -u http://target.com -w wordlist.txt    # custom wordlist
./spider.sh -u http://target.com -s 200,403 -o out  # filter codes, save output
```

### options

- `-u` : target url (required)
- `-w` : wordlist file (uses built-in list if not specified)
- `-s` : http status codes to report (default: 200,301,302,403)
- `-o` : output file
- `-t` : connection timeout in seconds (default: 5)
