# DedDNS

Async subdomain liveness checker. Feed it a list of subdomains and it probes each one over DNS, HTTPS and HTTP, then sorts them into categories: live, behind Cloudflare, WAF-protected, TLS problems, wildcard look-alikes, HTTP errors and dead.

**Pure standard library.** No `pip install`, no `requirements.txt`, no compiled dependencies.

```
▓█████▄ ▓█████ ▓█████▄ ▓█████▄  ███▄    █   ██████
▒██▀ ██▌▓█   ▀ ▒██▀ ██▌▒██▀ ██▌ ██ ▀█   █ ▒██    ▒
░██   █▌▒███   ░██   █▌░██   █▌▓██  ▀█ ██▒░ ▓██▄
░▓█▄   ▌▒▓█  ▄ ░▓█▄   ▌░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒
░▒████▓ ░▒████▒░▒████▓ ░▒████▓ ▒██░   ▓██░▒██████▒▒
   :: subdomain liveness scanner ::
```

Requirements: **Python 3.8 or newer**

## Usage

```sh
# scan a file, show the dashboard, save per-category lists in the current dir
python3 deddns.py subs.txt

# faster scan, shorter timeout, nothing written to disk
python3 deddns.py subs.txt -c 100 -t 6 --no-save

# pipe straight from another tool
subfinder -d example.com -silent | python3 deddns.py -

# query a specific resolver and also write a JSON report
python3 deddns.py subs.txt --resolver 1.1.1.1 --json report.json

# feed live URLs into other tools via jq
python3 deddns.py subs.txt --json - 2>/dev/null \
  | jq -r '.results[] | select(.label=="LIVE") | .url'
```

Run `python3 deddns.py --help` for the full option list.

## Categories

Each host is classified by its best response, in this priority order:

| Tag  | Meaning                                              |
|------|------------------------------------------------------|
| LIVE | answers 2xx/3xx, no WAF in front                     |
| CF   | answers 2xx/3xx via Cloudflare                       |
| WAF  | 401/403/429 or a WAF/bot challenge page              |
| TLS  | only reachable with certificate checks off           |
| WILD | same response as a random subdomain (likely wildcard)|
| ERR  | server is up but returns 4xx/5xx                      |
| DEAD | no DNS record or no HTTP(S) answer                   |

## Output

- **Terminal** — a live ASCII dashboard while scanning, then one table per
  category. No color, no emoji. Falls back to one line per host when piped or
  with `--plain`.
- **Text files** — with `--save` (default), each category's URLs are appended to
  `<base>_<category>.txt`, skipping URLs already present so repeated runs
  accumulate.
- **JSON** — `--json PATH` writes a full report (meta, per-category counts and
  every result); `--json -` prints it to stdout and sends everything else to
  stderr.

`Ctrl-C` stops the scan but still prints, saves and exports whatever finished.

## Legal

For use only against hosts you own or are explicitly authorized to test.
