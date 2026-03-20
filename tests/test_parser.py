import pytest
from datetime import datetime
from logsentry.parser import parse_line, parse_log_file, count_parseable_lines


# --- parse_line tests ---

class TestParseLine:
    def test_combined_format(self):
        line = '192.168.1.1 - - [15/Mar/2026:08:12:01 +0000] "GET /index.html HTTP/1.1" 200 5423 "https://google.com/" "Mozilla/5.0"'
        entry = parse_line(line)

        assert entry is not None
        assert entry.ip == "192.168.1.1"
        assert entry.method == "GET"
        assert entry.path == "/index.html"
        assert entry.status == 200
        assert entry.size == 5423
        assert entry.referrer == "https://google.com/"
        assert entry.user_agent == "Mozilla/5.0"

    def test_common_log_format(self):
        line = '10.0.0.1 - frank [10/Oct/2025:13:55:36 -0700] "GET /api/users HTTP/1.0" 200 2326'
        entry = parse_line(line)

        assert entry is not None
        assert entry.ip == "10.0.0.1"
        assert entry.status == 200
        assert entry.path == "/api/users"

    def test_post_request(self):
        line = '172.16.0.1 - - [01/Jan/2026:00:00:00 +0000] "POST /login HTTP/1.1" 401 128 "-" "Mozilla/5.0"'
        entry = parse_line(line)

        assert entry is not None
        assert entry.method == "POST"
        assert entry.status == 401

    def test_empty_line_returns_none(self):
        assert parse_line("") is None
        assert parse_line("   ") is None
        assert parse_line("\n") is None

    def test_garbage_returns_none(self):
        assert parse_line("this is not a log line") is None
        assert parse_line("12345") is None
        assert parse_line("GET /index.html") is None

    def test_dash_size_becomes_zero(self):
        line = '10.0.0.1 - - [15/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 304 - "-" "Mozilla/5.0"'
        entry = parse_line(line)

        assert entry is not None
        assert entry.size == 0

    def test_is_error_property(self):
        line_ok = '10.0.0.1 - - [15/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
        line_err = '10.0.0.1 - - [15/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 500 100 "-" "Mozilla/5.0"'

        assert parse_line(line_ok).is_error is False
        assert parse_line(line_err).is_error is True

    def test_404_is_error(self):
        line = '10.0.0.1 - - [15/Mar/2026:08:00:00 +0000] "GET /nope HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        assert parse_line(line).is_error is True

    def test_timestamp_parsing(self):
        line = '10.0.0.1 - - [25/Dec/2025:23:59:59 +0000] "GET / HTTP/1.1" 200 100 "-" "test"'
        entry = parse_line(line)

        assert entry.timestamp.year == 2025
        assert entry.timestamp.month == 12
        assert entry.timestamp.day == 25


# --- parse_log_file tests ---

class TestParseLogFile:
    def test_parse_sample_log(self):
        entries = list(parse_log_file("sample_logs/access.log"))
        assert len(entries) > 0
        # every entry should have an IP and a status code
        for e in entries:
            assert e.ip != ""
            assert 100 <= e.status <= 599

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            list(parse_log_file("this_file_does_not_exist.log"))

    def test_not_a_file(self, tmp_path):
        # tmp_path is a directory, not a file
        with pytest.raises(ValueError):
            list(parse_log_file(str(tmp_path)))


# --- count_parseable_lines tests ---

class TestCountLines:
    def test_sample_log_count(self):
        count = count_parseable_lines("sample_logs/access.log")
        assert count > 0

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty.log"
        empty.write_text("")
        assert count_parseable_lines(str(empty)) == 0

    def test_all_garbage(self, tmp_path):
        junk = tmp_path / "junk.log"
        junk.write_text("not a log\nstill not\nnope\n")
        assert count_parseable_lines(str(junk)) == 0

    def test_mixed_content(self, tmp_path):
        mixed = tmp_path / "mixed.log"
        mixed.write_text(
            "garbage line\n"
            '10.0.0.1 - - [15/Mar/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "test"\n'
            "more garbage\n"
        )
        assert count_parseable_lines(str(mixed)) == 1
