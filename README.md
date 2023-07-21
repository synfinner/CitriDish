# CitriDish

This script is designed to help in identifying potential assets running NetScaler Gateway or AAA. In some cases, hosts may have both enabled.

I've added in the DTCERT's list of patched last-modified headers as a marker for potentially vulnerable assets. Please note that modified pages and proxies may interfere with this method. Please ensure that you manually validate your discovered assets.

## Setup

- Setup env: `python3 -m venv env`
- Activate: `source /env/bin/activate`
- Install any dependencies: `pip3 install -r requirements.txt`

## Running

Output from help: 

```
usage: citridish.py [-h] [--file FILE] [targets ...]

Identify if a system is running Citrix Gateway, or Citrix AAA.

positional arguments:
  targets               The IP address(es) or hostname(s) to check.

options:
  -h, --help            show this help message and exit
  --file FILE, -f FILE  Read targets from a file (one IP/hostname per line).
```

## Notes

At the moment, this script is relying on logon/logout paths. These may change or some may be different.

You may get an SSL error that contains: 

```
: Max retries exceeded with url: /vpn/logout.html (Caused by SSLError(SSLError(1, '[SSL: UNSAFE_LEGACY_RENEGOTIATION_DISABLED] unsafe legacy renegotiation disabled (_ssl.c:1002)')))
```

This is because SSL unsafe legacy renegotiation is disabled in Python and--not to shame people...but--several places still cannot figure out how to SSL/TLS.

Lastly, I know that there are scripts to pull versions via the hashes within Gateway JS resource parameters. Many of these haven't been updated and I'm not going to singlehandedly do it. 

[fox-srt Citrix Version Hashes gist](https://gist.github.com/fox-srt/c7eb3cbc6b4bf9bb5a874fa208277e86)