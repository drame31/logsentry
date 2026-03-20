# LogSentry

A command-line tool that analyzes server access logs (Apache, Nginx, CLF) to detect security threats and suspicious activity. It scans for SQL injection, XSS, brute force attempts, directory traversal, command injection, known scanner tools, and more.

Built in Python as a portfolio project to demonstrate log parsing, pattern matching, and security analysis concepts.

## How it works

LogSentry reads a log file line by line using a generator (so it doesn't choke on large files), parses each entry with regex, and runs every request through a detection engine that checks for known attack signatures. Results are printed to the terminal with color-coded severity levels, and can also be exported to JSON or CSV.

### What it detects

- **SQL Injection** (CRITICAL) — UNION SELECT, OR 1=1, DROP TABLE, etc.
- **Command Injection** (CRITICAL) — shell commands in URL parameters
- **XSS** (HIGH) — script tags, event handlers, javascript: URIs
- **Directory Traversal** (HIGH) — `../` sequences, `/etc/passwd` access
- **Brute Force** (HIGH) — repeated 401/403 responses from the same IP
- **Rate Abuse** (HIGH) — abnormally high request rates from a single IP
- **Automated Scanners** (MEDIUM) — Nikto, sqlmap, Nmap, Burp Suite, etc.
- **Sensitive Path Access** (MEDIUM) — `.env`, `.git`, `wp-admin`, `phpmyadmin`

## Getting started

```bash
git clone https://github.com/drame31/logsentry.git
cd logsentry
pip install -r requirements.txt
python main.py sample_logs/access.log
```

The repo includes a sample log file with a mix of normal traffic and various attacks so you can see it in action right away.

## Usage

```bash
# basic analysis (prints to terminal)
python main.py /var/log/apache2/access.log

# export to JSON
python main.py access.log -e json -o my_report

# export to JSON and CSV
python main.py access.log -e both -o security_audit

# adjust detection thresholds
python main.py access.log --brute-force-threshold 5 --rate-limit 50

# quiet mode — only export, no terminal output
python main.py access.log -e json -q
```

### Options

| Flag | What it does | Default |
|---|---|---|
| `logfile` | Path to the log file | required |
| `-e, --export` | `json`, `csv`, or `both` | terminal only |
| `-o, --output` | Output filename (no extension) | `logsentry_report` |
| `--brute-force-threshold` | Failed attempts to flag brute force | 10 |
| `--rate-limit` | Requests/min for rate abuse | 100 |
| `-q, --quiet` | Suppress terminal output | off |
| `-v, --version` | Print version | — |

### Exit codes

The program returns `0` if no threats are found, `1` if non-critical threats are found, and `2` if critical threats are detected. This makes it easy to plug into scripts or CI pipelines.

## Project structure

```
logsentry/
├── logsentry/
│   ├── __init__.py       # version
│   ├── parser.py         # log parsing (generator-based)
│   ├── analyzer.py       # threat detection engine
│   ├── reporter.py       # terminal output + JSON/CSV export
│   └── cli.py            # CLI argument handling
├── tests/
│   ├── test_parser.py    # parser tests
│   ├── test_analyzer.py  # detection engine tests
│   └── test_reporter.py  # export tests
├── sample_logs/
│   └── access.log        # sample log with attacks mixed in
├── main.py               # entry point
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Tests

45 tests covering the parser, every detection type, edge cases, and export functionality.

```bash
pip install pytest
pytest
```

## Dependencies

- **Python 3.10+**
- **[Rich](https://github.com/Textualize/rich)** — for terminal formatting and progress bars

Everything else is from the standard library: `re`, `argparse`, `dataclasses`, `collections`, `pathlib`, `csv`, `json`.

## License

MIT

## Author

Derek Muñoz Solís — [Portfolio](https://drame31.github.io) · [GitHub](https://github.com/drame31)
