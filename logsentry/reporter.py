import csv
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .analyzer import AnalysisResult

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "bold cyan",
    "LOW": "dim white",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}

console = Console()


def print_banner():
    banner = """
╦  ╔═╗╔═╗╔═╗╔═╗╔╗╔╔╦╗╦═╗╦ ╦
║  ║ ║║ ╦╚═╗║╣ ║║║ ║ ╠╦╝╚╦╝
╩═╝╚═╝╚═╝╚═╝╚═╝╝╚╝ ╩ ╩╚═ ╩  v1.0
    """
    console.print(banner, style="bold cyan")
    console.print("  Security Log Analyzer\n", style="dim")


def print_summary(result: AnalysisResult):
    severity = result.severity_counts
    threat_level = _get_threat_level(severity)

    text = Text()
    text.append("  Entries analyzed:  ", style="dim")
    text.append(f"{result.total_entries:,}\n", style="bold white")
    text.append("  Unique IPs:        ", style="dim")
    text.append(f"{result.unique_ips:,}\n", style="bold white")
    text.append("  Error rate:        ", style="dim")
    text.append(f"{result.error_rate:.1f}%\n", style="bold white")

    if result.time_range:
        text.append("  Time range:        ", style="dim")
        text.append(f"{result.time_range[0]}  →  {result.time_range[1]}\n", style="white")

    text.append("\n  Threats found:     ", style="dim")
    color = "bold red" if result.total_threats > 0 else "bold green"
    text.append(f"{result.total_threats}", style=color)

    text.append("\n  Threat level:      ", style="dim")
    text.append(f"{threat_level}\n", style=SEVERITY_COLORS.get(threat_level, "white"))

    text.append(f"\n  🔴 Critical: {severity['CRITICAL']}  ", style="bold red")
    text.append(f"🟠 High: {severity['HIGH']}  ", style="bold yellow")
    text.append(f"🟡 Medium: {severity['MEDIUM']}  ", style="bold cyan")
    text.append(f"🟢 Low: {severity['LOW']}", style="dim")

    console.print(Panel(
        text,
        title="[bold white] ANALYSIS SUMMARY [/]",
        border_style="cyan",
        box=box.DOUBLE_EDGE,
        padding=(1, 2),
    ))


def print_threats(result: AnalysisResult):
    if not result.threats:
        console.print(Panel(
            "  ✅ No threats detected. Logs look clean.",
            title="[bold green] THREATS [/]",
            border_style="green",
            padding=(1, 2),
        ))
        return

    # sort so critical stuff shows up first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_threats = sorted(result.threats, key=lambda t: order.get(t.severity, 4))

    table = Table(
        title="DETECTED THREATS",
        box=box.ROUNDED,
        border_style="red",
        show_lines=True,
        title_style="bold red",
        padding=(0, 1),
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Category", style="bold white", width=22)
    table.add_column("Source IP", style="cyan", width=16)
    table.add_column("Hits", justify="center", width=5)
    table.add_column("Evidence", width=40, style="dim")

    for i, threat in enumerate(sorted_threats, 1):
        icon = SEVERITY_ICONS.get(threat.severity, "⚪")
        sev_color = SEVERITY_COLORS.get(threat.severity, "white")

        table.add_row(
            str(i),
            Text(f"{icon} {threat.severity}", style=sev_color),
            threat.category,
            threat.source_ip,
            str(threat.count),
            threat.evidence[:50],
        )

    console.print()
    console.print(table)


def print_top_ips(result: AnalysisResult, limit: int = 10):
    if not result.top_ips:
        return

    table = Table(
        title="TOP REQUESTING IPs",
        box=box.SIMPLE_HEAVY,
        border_style="cyan",
        title_style="bold cyan",
    )
    table.add_column("Rank", style="dim", width=5, justify="center")
    table.add_column("IP Address", style="bold white", width=18)
    table.add_column("Requests", justify="right", width=10)
    table.add_column("% of Total", justify="right", width=10)

    for i, (ip, count) in enumerate(result.top_ips[:limit], 1):
        pct = (count / result.total_entries) * 100 if result.total_entries else 0
        bar = "█" * int(pct / 2)

        table.add_row(str(i), ip, f"{count:,}", f"{pct:.1f}%  {bar}")

    console.print()
    console.print(table)


def print_status_distribution(result: AnalysisResult):
    if not result.status_distribution:
        return

    table = Table(
        title="HTTP STATUS DISTRIBUTION",
        box=box.SIMPLE_HEAVY,
        border_style="cyan",
        title_style="bold cyan",
    )
    table.add_column("Status", width=8, justify="center")
    table.add_column("Count", justify="right", width=10)
    table.add_column("Category", width=22)
    table.add_column("Distribution", width=30)

    categories = {
        2: ("✅ Success", "green"),
        3: ("↪ Redirect", "yellow"),
        4: ("⚠ Client Error", "bold yellow"),
        5: ("❌ Server Error", "bold red"),
    }

    for status, count in sorted(result.status_distribution.items()):
        label, color = categories.get(status // 100, ("Unknown", "dim"))
        pct = (count / result.total_entries) * 100
        bar = "█" * int(pct / 2)

        table.add_row(
            Text(str(status), style=color),
            f"{count:,}",
            label,
            f"{pct:.1f}%  {bar}",
        )

    console.print()
    console.print(table)


def print_full_report(result: AnalysisResult):
    print_banner()
    print_summary(result)
    print_threats(result)
    print_top_ips(result)
    print_status_distribution(result)
    console.print()


# -- Export --

def export_json(result: AnalysisResult, output_path: str):
    data = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_entries": result.total_entries,
            "unique_ips": result.unique_ips,
            "error_rate": round(result.error_rate, 2),
            "total_threats": result.total_threats,
            "severity_counts": result.severity_counts,
            "time_range": result.time_range,
        },
        "threats": [
            {
                "category": t.category,
                "severity": t.severity,
                "description": t.description,
                "evidence": t.evidence,
                "source_ip": t.source_ip,
                "count": t.count,
            }
            for t in result.threats
        ],
        "top_ips": [{"ip": ip, "requests": c} for ip, c in result.top_ips],
        "status_distribution": {str(k): v for k, v in result.status_distribution.items()},
        "methods": result.methods_distribution,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    console.print(f"\n  💾 JSON report saved to: [bold cyan]{output_path}[/]")


def export_csv(result: AnalysisResult, output_path: str):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Severity", "Source IP", "Count", "Description", "Evidence"])
        for t in result.threats:
            writer.writerow([t.category, t.severity, t.source_ip, t.count, t.description, t.evidence])

    console.print(f"  💾 CSV report saved to:  [bold cyan]{output_path}[/]")


def _get_threat_level(severity_counts: dict[str, int]) -> str:
    if severity_counts.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if severity_counts.get("HIGH", 0) > 0:
        return "HIGH"
    if severity_counts.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    if severity_counts.get("LOW", 0) > 0:
        return "LOW"
    return "NONE"
