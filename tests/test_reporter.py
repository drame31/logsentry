import json
import csv
from logsentry.analyzer import AnalysisResult, Threat
from logsentry.reporter import export_json, export_csv


def _sample_result():
    """Build a minimal AnalysisResult for testing exports."""
    result = AnalysisResult()
    result.total_entries = 50
    result.unique_ips = 5
    result.error_rate = 20.0
    result.total_threats = 2
    result.time_range = ("2026-03-15 08:00:00", "2026-03-15 10:00:00")
    result.status_distribution = {200: 40, 404: 10}
    result.methods_distribution = {"GET": 45, "POST": 5}
    result.top_ips = [("10.0.0.1", 30), ("10.0.0.2", 20)]
    result.threats = [
        Threat(
            category="SQL Injection",
            severity="CRITICAL",
            description="SQLi from 10.0.0.1 (3 hits)",
            evidence="/search?q='+OR+1=1",
            source_ip="10.0.0.1",
            count=3,
        ),
        Threat(
            category="Automated Scanner",
            severity="MEDIUM",
            description="Scanner from 10.0.0.2 (5 hits)",
            evidence="Nikto/2.1.6",
            source_ip="10.0.0.2",
            count=5,
        ),
    ]
    return result


class TestJSONExport:
    def test_creates_valid_json(self, tmp_path):
        out = str(tmp_path / "report.json")
        export_json(_sample_result(), out)

        with open(out) as f:
            data = json.load(f)

        assert data["summary"]["total_entries"] == 50
        assert data["summary"]["total_threats"] == 2
        assert len(data["threats"]) == 2
        assert data["threats"][0]["category"] == "SQL Injection"

    def test_creates_parent_dirs(self, tmp_path):
        out = str(tmp_path / "nested" / "dir" / "report.json")
        export_json(_sample_result(), out)

        with open(out) as f:
            data = json.load(f)
        assert data["summary"]["total_entries"] == 50

    def test_empty_result(self, tmp_path):
        out = str(tmp_path / "empty.json")
        export_json(AnalysisResult(), out)

        with open(out) as f:
            data = json.load(f)
        assert data["summary"]["total_entries"] == 0
        assert data["threats"] == []


class TestCSVExport:
    def test_creates_valid_csv(self, tmp_path):
        out = str(tmp_path / "report.csv")
        export_csv(_sample_result(), out)

        with open(out) as f:
            reader = list(csv.reader(f))

        # header + 2 threats
        assert len(reader) == 3
        assert reader[0][0] == "Category"
        assert reader[1][0] == "SQL Injection"
        assert reader[2][0] == "Automated Scanner"

    def test_empty_result_only_header(self, tmp_path):
        out = str(tmp_path / "empty.csv")
        export_csv(AnalysisResult(), out)

        with open(out) as f:
            reader = list(csv.reader(f))
        assert len(reader) == 1  # just the header row
