import json
import datetime
from pathlib import Path
from risk_scorer import compute_overall_risk


def generate_md_report(scored_chunks, delta, config, output_path):
    lines = []
    overall = compute_overall_risk(scored_chunks)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append("# SDec Report")
    lines.append("")
    lines.append(f"**{now}**")
    lines.append("")
    lines.append(f"## {overall['overall_level']} (Score: {overall['overall_score']})")
    lines.append("")
    lines.append(f"| | |")
    lines.append(f"|---|---|")
    lines.append(f"| Findings | {overall['total_findings']} |")
    lines.append(f"| Critical | {overall['critical_count']} |")
    lines.append(f"| High | {overall['high_count']} |")
    lines.append("")

    if delta:
        lines.append("## Delta")
        lines.append("")
        if delta.get("new_findings"):
            lines.append(f"### New ({len(delta['new_findings'])})")
            for nf in delta["new_findings"]:
                f = nf["finding"]
                lines.append(f"- **{f['id']}** [{f['severity']}] {f['title']} — `{f.get('detail', '')}`")
            lines.append("")

        if delta.get("resolved_findings"):
            lines.append(f"### Resolved ({len(delta['resolved_findings'])})")
            for rf in delta["resolved_findings"]:
                f = rf["finding"]
                lines.append(f"- ~~{f['id']}~~ {f['title']}")
            lines.append("")

    lines.append("---")
    lines.append("")

    layer_order = ["01_hardware", "02_boot", "03_memory", "04_persistence", "05_filesystem", "06_application", "07_optimization", "08_network"]

    for layer_id in layer_order:
        if layer_id not in scored_chunks:
            continue

        chunk = scored_chunks[layer_id]
        summary = chunk["summary"]

        lines.append(f"## [{summary['layer_risk']}] {chunk['layer_name']}")
        lines.append("")

        if summary["total_findings"] == 0:
            lines.append("> No findings")
            lines.append("")
            continue

        lines.append(f"| | |")
        lines.append(f"|---|---|")
        lines.append(f"| Risk | {summary['layer_risk']} |")
        lines.append(f"| Findings | {summary['total_findings']} |")
        lines.append(f"| Max Score | {summary['max_score']} |")
        lines.append("")

        lines.append("### Findings")
        lines.append("")
        lines.append("| ID | Score | MITRE | Title | Detail |")
        lines.append("|---|---|---|---|---|")

        for f in chunk["findings"]:
            mitre_link = f"[{f['mitre']}](https://attack.mitre.org/techniques/{f['mitre'].replace('.', '/')})" if f["mitre"] != "N/A" else "—"
            detail = f.get("detail", "").replace("|", " / ")
            lines.append(f"| {f['id']} | {f['score']} | {mitre_link} | {f['title']} | `{detail}` |")

        lines.append("")

        data = chunk.get("data", {})
        if data:
            lines.append("<details>")
            lines.append(f"<summary>Raw Data</summary>")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(data, indent=2, ensure_ascii=False, default=str)[:5000])
            lines.append("```")
            lines.append("</details>")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append(f"*SDec — {now}*")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
