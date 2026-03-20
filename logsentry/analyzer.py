import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .parser import LogEntry


# ---------------------------------------------------------------------------
# Attack signatures
# Each group is a list of compiled regex patterns. When any pattern in a group
# matches a request path (or user-agent for scanners), we flag it.
# ---------------------------------------------------------------------------

SQLI_PATTERNS = [
    re.compile(r"(\bunion\b.*\bselect\b)", re.IGNORECASE),
    re.compile(r"(\bor\b[\s+]+1[\s+]*=[\s+]*1)", re.IGNORECASE),
    re.compile(r"(--|;)[\s+]*(drop|alter|delete|insert|update)", re.IGNORECASE),
    re.compile(r"'[\s+]*(or|and)[\s+]+'", re.IGNORECASE),
    re.compile(r"(\bselect\b.*\bfrom\b.*\bwhere\b)", re.IGNORECASE),
    re.compile(r"(\bexec\b|\bexecute\b)[\s+]*\(", re.IGNORECASE),
    re.compile(r"(\bwaitfor\b[\s+]+\bdelay\b)", re.IGNORECASE),
    re.compile(r"(\bbenchmark\b[\s+]*\()", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(error|load|click|mouseover)\s*=", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+onerror", re.IGNORECASE),
    re.compile(r"<\s*iframe", re.IGNORECASE),
    re.compile(r"<\s*svg[^>]+onload", re.IGNORECASE),
    re.compile(r"document\.(cookie|write|location)", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE),
]

TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e%2f", re.IGNORECASE),
    re.compile(r"%2e%2e/", re.IGNORECASE),
    re.compile(r"\.\.%2f", re.IGNORECASE),
    re.compile(r"/etc/(passwd|shadow|hosts)"),
    re.compile(r"/proc/self/"),
    re.compile(r"(boot\.ini|win\.ini)", re.IGNORECASE),
]

CMD_INJECTION_PATTERNS = [
    re.compile(r";\s*(ls|cat|rm|wget|curl|bash|sh|nc|python|perl|ruby)\b"),
    re.compile(r"\|\s*(ls|cat|rm|wget|curl|bash|sh|nc)\b"),
    re.compile(r"\$\(.*\)"),
    re.compile(r"`.*`"),
]

SCANNER_AGENTS = [
    re.compile(r"(nikto|sqlmap|nmap|masscan|dirbuster|gobuster)", re.IGNORECASE),
    re.compile(r"(burpsuite|owasp|zap|w3af|acunetix)", re.IGNORECASE),
    re.compile(r"(havij|nessus|openvas|metasploit)", re.IGNORECASE),
    re.compile(r"(python-requests|go-http-client|curl/)"),
]

SENSITIVE_PATHS = [
    re.compile(r"/(\.env|\.git|\.htaccess|\.htpasswd)"),
    re.compile(r"/(wp-admin|wp-login|xmlrpc\.php)", re.IGNORECASE),
    re.compile(r"/(phpmyadmin|adminer|phpinfo)", re.IGNORECASE),
    re.compile(r"/(admin|administrator|manager|console)", re.IGNORECASE),
    re.compile(r"/(backup|dump|database|config)\.", re.IGNORECASE),
    re.compile(r"/\.(aws|docker|kube)/", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Data classes for results
# ---------------------------------------------------------------------------

@dataclass
class Threat:
    category: str       # "SQL Injection", "XSS", etc.
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    evidence: str       # the actual path or user-agent that triggered it
    source_ip: str
    count: int = 1
    entries: list[LogEntry] = field(default_factory=list)


@dataclass
class AnalysisResult:
    total_entries: int = 0
    total_threats: int = 0
    threats: list[Threat] = field(default_factory=list)
    status_distribution: dict[int, int] = field(default_factory=dict)
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_user_agents: list[tuple[str, int]] = field(default_factory=list)
    time_range: tuple[str, str] | None = None
    methods_distribution: dict[str, int] = field(default_factory=dict)
    unique_ips: int = 0
    error_rate: float = 0.0

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for t in self.threats:
            counts[t.severity] = counts.get(t.severity, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class LogAnalyzer:
    def __init__(self, brute_force_threshold: int = 10, rate_limit_threshold: int = 100):
        self.brute_force_threshold = brute_force_threshold
        self.rate_limit_threshold = rate_limit_threshold

    def analyze(self, entries: list[LogEntry]) -> AnalysisResult:
        """Run the full analysis pipeline on a list of parsed log entries."""
        result = AnalysisResult()
        result.total_entries = len(entries)

        if not entries:
            return result

        # aggregate stats in a single pass
        ip_counts = Counter()
        status_counts = Counter()
        path_counts = Counter()
        agent_counts = Counter()
        method_counts = Counter()
        failed_auth: dict[str, list[LogEntry]] = defaultdict(list)
        ip_timestamps: dict[str, list] = defaultdict(list)

        for entry in entries:
            ip_counts[entry.ip] += 1
            status_counts[entry.status] += 1
            path_counts[entry.path] += 1
            agent_counts[entry.user_agent] += 1
            method_counts[entry.method] += 1
            ip_timestamps[entry.ip].append(entry.timestamp)

            if entry.status in (401, 403):
                failed_auth[entry.ip].append(entry)

        result.status_distribution = dict(status_counts)
        result.top_paths = path_counts.most_common(15)
        result.top_ips = ip_counts.most_common(15)
        result.top_user_agents = agent_counts.most_common(10)
        result.methods_distribution = dict(method_counts)
        result.unique_ips = len(ip_counts)

        error_count = sum(1 for e in entries if e.is_error)
        result.error_rate = (error_count / len(entries)) * 100

        timestamps = [e.timestamp for e in entries]
        result.time_range = (
            min(timestamps).strftime("%Y-%m-%d %H:%M:%S"),
            max(timestamps).strftime("%Y-%m-%d %H:%M:%S"),
        )

        # run all detectors and collect threats
        threats: list[Threat] = []

        # pattern-based detectors (path scanning)
        # each tuple: (patterns, field_to_check, category_name, severity)
        path_checks = [
            (SQLI_PATTERNS,      "path",       "SQL Injection",              "CRITICAL"),
            (CMD_INJECTION_PATTERNS, "path",    "Command Injection",         "CRITICAL"),
            (XSS_PATTERNS,       "path",       "Cross-Site Scripting (XSS)", "HIGH"),
            (TRAVERSAL_PATTERNS, "path",       "Directory Traversal",        "HIGH"),
            (SENSITIVE_PATHS,    "path",       "Sensitive Path Access",      "MEDIUM"),
            (SCANNER_AGENTS,     "user_agent", "Automated Scanner",          "MEDIUM"),
        ]

        for patterns, field, category, severity in path_checks:
            threats.extend(
                self._scan_for_patterns(entries, patterns, field, category, severity)
            )

        # brute force detection (based on failed auth counts)
        threats.extend(self._detect_brute_force(failed_auth))

        # rate abuse / DDoS detection
        threats.extend(self._detect_rate_abuse(ip_counts, ip_timestamps))

        result.threats = threats
        result.total_threats = len(threats)
        return result

    def _scan_for_patterns(
        self,
        entries: list[LogEntry],
        patterns: list[re.Pattern],
        field: str,
        category: str,
        severity: str,
    ) -> list[Threat]:
        """
        Generic scanner: checks a specific field of each entry against a list
        of regex patterns, groups matches by IP, and returns one Threat per IP.
        This avoids repeating the same loop logic for every attack type.
        """
        flagged: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in entries:
            value = getattr(entry, field)
            for pat in patterns:
                if pat.search(value):
                    flagged[entry.ip].append(entry)
                    break  # one match is enough, skip other patterns

        threats = []
        for ip, matched_entries in flagged.items():
            # for sensitive path access, show which paths were hit
            if category == "Sensitive Path Access":
                unique_paths = list({e.path for e in matched_entries})
                evidence = ", ".join(unique_paths[:3])
            else:
                evidence = getattr(matched_entries[0], field)[:120]

            threats.append(Threat(
                category=category,
                severity=severity,
                description=f"{category} detected from {ip} ({len(matched_entries)} hits)",
                evidence=evidence,
                source_ip=ip,
                count=len(matched_entries),
                entries=matched_entries[:5],
            ))

        return threats

    def _detect_brute_force(self, failed_auth: dict[str, list[LogEntry]]) -> list[Threat]:
        threats = []
        for ip, entries in failed_auth.items():
            if len(entries) >= self.brute_force_threshold:
                threats.append(Threat(
                    category="Brute Force",
                    severity="HIGH",
                    description=f"{len(entries)} failed auth attempts from {ip}",
                    evidence=f"{len(entries)} requests returned 401/403",
                    source_ip=ip,
                    count=len(entries),
                    entries=entries[:5],
                ))
        return threats

    def _detect_rate_abuse(self, ip_counts: Counter, ip_timestamps: dict) -> list[Threat]:
        threats = []
        for ip, count in ip_counts.items():
            if count < self.rate_limit_threshold:
                continue

            ts_sorted = sorted(ip_timestamps[ip])
            if len(ts_sorted) >= 2:
                delta_secs = (ts_sorted[-1] - ts_sorted[0]).total_seconds()
                rate = count / (delta_secs / 60) if delta_secs > 0 else count
            else:
                rate = count

            if rate >= self.rate_limit_threshold:
                threats.append(Threat(
                    category="Rate Abuse / DDoS",
                    severity="HIGH",
                    description=f"Abnormal request rate from {ip}: ~{rate:.0f} req/min",
                    evidence=f"{count} total requests in analyzed period",
                    source_ip=ip,
                    count=count,
                ))

        return threats
