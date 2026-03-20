import re
from dataclasses import dataclass
from datetime import datetime
from typing import Generator
from pathlib import Path


@dataclass
class LogEntry:
    """Single parsed log entry with all the fields we care about."""
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: int
    referrer: str
    user_agent: str
    raw: str

    @property
    def is_error(self) -> bool:
        return self.status >= 400


# regex for Apache Combined / Nginx format
_COMBINED = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

# regex for Common Log Format (no referrer/user-agent)
_COMMON = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

_PATTERNS = [_COMBINED, _COMMON]

_TS_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
]


def _parse_timestamp(raw: str) -> datetime:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    # fallback — shouldn't happen with valid logs but just in case
    return datetime.now()


def parse_line(line: str) -> LogEntry | None:
    """Try to parse a single log line. Returns None if it doesn't match any format."""
    line = line.strip()
    if not line:
        return None

    for pattern in _PATTERNS:
        m = pattern.match(line)
        if m:
            d = m.groupdict()
            raw_size = d.get("size", "0")

            return LogEntry(
                ip=d["ip"],
                timestamp=_parse_timestamp(d["timestamp"]),
                method=d.get("method", "GET"),
                path=d.get("path", "/"),
                status=int(d["status"]),
                size=int(raw_size) if raw_size.isdigit() else 0,
                referrer=d.get("referrer", "-"),
                user_agent=d.get("user_agent", "-"),
                raw=line,
            )

    return None


def parse_log_file(filepath: str) -> Generator[LogEntry, None, None]:
    """
    Generator that yields LogEntry objects from a log file.
    Doesn't load the whole file into memory so it can handle big files.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")
    if not path.is_file():
        raise ValueError(f"Not a file: {filepath}")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            entry = parse_line(line)
            if entry is not None:
                yield entry


def count_parseable_lines(filepath: str) -> int:
    """Quick pass to count how many lines we can actually parse (for the progress bar)."""
    count = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if parse_line(line) is not None:
                count += 1
    return count
