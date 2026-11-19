"""Local, escaped HTML investigation report generation."""

from datetime import datetime
from collections import Counter
from html import escape
from pathlib import Path

from packetlens.models import CaptureAnalysis


def build_html_report(analysis: CaptureAnalysis, generated_at: datetime | None = None) -> str:
    generated = generated_at or datetime.now().astimezone()
    def capture_time(value):
        if value is None:
            return "Unavailable"
        try:
            return datetime.fromtimestamp(value).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        except (OSError, OverflowError, ValueError):
            return f"Unix {value:.6f}"
    protocols = "".join(f"<tr><td>{escape(name)}</td><td>{count}</td></tr>"
                        for name, count in analysis.protocol_counts.items())
    talkers = "".join(f"<tr><td>{escape(address)}</td><td>{count}</td></tr>"
                      for address, count in analysis.top_talkers)
    domain_counts = Counter()
    for activity in analysis.dns_activities:
        domain_counts[activity.domain] += activity.query_count
    domains = "".join(
        f"<tr><td>{escape(domain)}</td><td>{count}</td></tr>"
        for domain, count in domain_counts.most_common(10)) or "<tr><td colspan='2'>No DNS queries observed</td></tr>"
    conversations = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            escape(item.endpoint_a), escape(item.endpoint_b), escape(item.protocol),
            item.packet_count, item.total_bytes,
            escape(item.tcp_state + (f" Flags: {item.tcp_flags}." if item.tcp_flags else "")))
        for item in analysis.conversations[:10]) or "<tr><td colspan='6'>No TCP or UDP conversations</td></tr>"

    def finding_evidence(finding):
        preview = finding.references[:20]
        numbers = ", ".join(map(str, preview)) or "None"
        if len(finding.references) > len(preview):
            return (f"Packet evidence preview: {numbers} "
                    f"({len(preview)} of {len(finding.references)} references shown). ")
        return f"Packet evidence: {numbers} ({len(finding.references)} total references). "

    findings = "".join(
        "<article><span class='badge'>{}</span><h3>{}</h3><p>{}</p><small>{}</small></article>".format(
            escape(f.classification), escape(f.title), escape(f.description),
            escape(f"Triggering rule: {f.triggering_rule}. Why it matters: {f.why_it_matters}. "
                   + (f"Relevant endpoints: {', '.join(f.endpoints)}. " if f.endpoints else "")
                   + (f"Related IP: {f.related_ip}. " if f.related_ip else "")
                   + finding_evidence(f)
                   + "Next step: " + f.suggested_next_step))
        for f in analysis.findings) or "<p>No heuristic observations were generated.</p>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>PacketLens Report</title>
<style>body{{font:15px Segoe UI,Arial;color:#182033;background:#f4f7fb;margin:0}}main{{max-width:960px;margin:32px auto;padding:0 24px}}header,section,article{{background:white;border:1px solid #dce3ef;border-radius:12px;padding:20px;margin:14px 0}}h1,h2,h3{{margin-top:0}}table{{border-collapse:collapse;width:100%}}td,th{{padding:9px;border-bottom:1px solid #e8edf4;text-align:left}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.metric{{background:#eef4ff;padding:12px;border-radius:8px}}.badge{{float:right;background:#e7efff;color:#174ea6;padding:4px 9px;border-radius:999px}}small{{color:#5f6b7a}}</style></head>
<body><main><header><h1>PacketLens Investigation Report</h1><p>{escape(analysis.filename)} — {escape(analysis.source_mode.title())} capture</p><small>Generated locally {escape(generated.strftime('%Y-%m-%d %H:%M:%S %Z'))}</small></header>
<section><h2>Capture information</h2><div class="grid"><div class="metric"><b>{len(analysis.packets)}</b><br>Packets</div><div class="metric"><b>{analysis.duration:.3f}s</b><br>Duration</div><div class="metric"><b>{analysis.total_bytes:,}</b><br>Captured bytes</div><div class="metric"><b>{len(analysis.unique_ips)}</b><br>Unique IPs</div></div><p>State: {escape(analysis.capture_state)}. Start: {escape(capture_time(analysis.start_time))}. End: {escape(capture_time(analysis.end_time))}.</p></section>
<section><h2>Investigation summary</h2><p>{escape(analysis.investigation_summary)}</p><p>{len(analysis.conversations):,} conversations; {sum(item.query_count for item in analysis.dns_activities):,} DNS queries; {len(analysis.findings):,} security observations.</p></section>
<section><h2>Protocol distribution</h2><table><tr><th>Protocol</th><th>Packets</th></tr>{protocols}</table></section>
<section><h2>Top IP addresses</h2><table><tr><th>Address</th><th>Packets involving address</th></tr>{talkers}</table></section>
<section><h2>DNS investigation</h2><table><tr><th>Most frequently queried domain</th><th>Queries</th></tr>{domains}</table></section>
<section><h2>Top network conversations</h2><table><tr><th>Endpoint A</th><th>Endpoint B</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>TCP evidence</th></tr>{conversations}</table></section>
<section><h2>Security observations</h2>{findings}<p><small>These rule-based observations are investigative leads, not proof of malicious activity. Results depend on capture completeness.</small></p></section>
</main></body></html>"""


def write_html_report(analysis: CaptureAnalysis, destination: str | Path) -> Path:
    path = Path(destination)
    path.write_text(build_html_report(analysis), encoding="utf-8")
    return path
