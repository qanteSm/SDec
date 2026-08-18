import json
import datetime
from pathlib import Path
from risk_scorer import compute_overall_risk


def _esc(text):
    if not isinstance(text, str):
        text = str(text)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def generate_html_report(scored_chunks, delta, config, output_path):
    overall = compute_overall_risk(scored_chunks)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    layer_order = [
        "01_hardware", "02_boot", "03_memory", "04_persistence",
        "05_filesystem", "06_application", "07_optimization", "08_network"
    ]

    findings_json = {}
    for lid in layer_order:
        if lid in scored_chunks:
            findings_json[lid] = scored_chunks[lid].get("findings", [])

    all_data = {}
    for lid in layer_order:
        if lid in scored_chunks:
            all_data[lid] = scored_chunks[lid].get("data", {})

    html_parts = []
    html_parts.append(f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SDec Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{
--bg:#f8fafc;--card-bg:#ffffff;
--text:#0f172a;--text-muted:#64748b;--text-light:#94a3b8;
--border:#e2e8f0;--border-dark:#cbd5e1;
--critical:#dc2626;--critical-bg:#fef2f2;--critical-border:#fecaca;
--high:#ea580c;--high-bg:#fff7ed;--high-border:#ffedd5;
--medium:#d97706;--medium-bg:#fffbeb;--medium-border:#fef3c7;
--low:#16a34a;--low-bg:#f0fdf4;--low-border:#dcfce7;
--clean:#059669;--clean-bg:#ecfdf5;--clean-border:#a7f3d0;
--info:#2563eb;--info-bg:#eff6ff;--info-border:#dbeafe;
}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;padding:24px 16px}}
.container{{max-width:1200px;margin:0 auto}}
.header{{padding:20px 0 16px;border-bottom:1px solid var(--border);margin-bottom:24px;display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:12px}}
.header h1{{font-size:1.8rem;font-weight:700;color:var(--text);letter-spacing:-0.5px}}
.header .subtitle{{color:var(--text-muted);font-size:0.88rem}}
.overall-card{{background:var(--card-bg);border:1px solid var(--border);border-radius:6px;padding:20px 24px;margin-bottom:24px;display:flex;align-items:center;gap:24px;flex-wrap:wrap}}
.risk-box{{padding:12px 20px;border-radius:4px;text-align:center;border:1px solid var(--border);min-width:120px}}
.risk-box .score{{font-size:2rem;font-weight:700;line-height:1}}
.risk-box .label{{font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}}
.overall-stats{{flex:1;display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px}}
.stat-item{{background:#f8fafc;border:1px solid var(--border);border-radius:4px;padding:12px;text-align:center}}
.stat-item .value{{font-size:1.4rem;font-weight:700;color:var(--text)}}
.stat-item .label{{font-size:0.75rem;color:var(--text-muted);margin-top:2px}}
.controls{{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap;align-items:center}}
.filter-btn{{padding:6px 14px;border-radius:4px;border:1px solid var(--border);background:var(--card-bg);color:var(--text);cursor:pointer;font-size:0.82rem;font-weight:500}}
.filter-btn:hover{{background:#f1f5f9;border-color:var(--border-dark)}}
.filter-btn.active{{background:var(--text);color:#ffffff;border-color:var(--text)}}
.filter-btn.active-critical{{background:var(--critical);border-color:var(--critical);color:#ffffff}}
.filter-btn.active-high{{background:var(--high);border-color:var(--high);color:#ffffff}}
.filter-btn.active-medium{{background:var(--medium);border-color:var(--medium);color:#ffffff}}
.filter-btn.active-low{{background:var(--low);border-color:var(--low);color:#ffffff}}
.search-box{{flex:1;min-width:220px;padding:7px 12px;border-radius:4px;border:1px solid var(--border);background:var(--card-bg);color:var(--text);font-size:0.85rem;outline:none}}
.search-box:focus{{border-color:var(--text);background:#ffffff}}
.layer-section{{margin-bottom:16px;border:1px solid var(--border);border-radius:6px;background:var(--card-bg);overflow:hidden}}
.layer-header{{padding:14px 18px;cursor:pointer;display:flex;align-items:center;gap:12px;user-select:none;background:var(--card-bg);border-bottom:1px solid transparent}}
.layer-section.open .layer-header{{border-bottom-color:var(--border)}}
.layer-header:hover{{background:#f8fafc}}
.layer-title{{flex:1}}
.layer-title h2{{font-size:1rem;font-weight:600;color:var(--text)}}
.layer-title .meta{{font-size:0.78rem;color:var(--text-muted)}}
.layer-badge{{padding:2px 10px;border-radius:4px;font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.3px}}
.badge-critical{{background:var(--critical-bg);color:var(--critical);border:1px solid var(--critical-border)}}
.badge-high{{background:var(--high-bg);color:var(--high);border:1px solid var(--high-border)}}
.badge-medium{{background:var(--medium-bg);color:var(--medium);border:1px solid var(--medium-border)}}
.badge-low{{background:var(--low-bg);color:var(--low);border:1px solid var(--low-border)}}
.badge-clean{{background:var(--clean-bg);color:var(--clean);border:1px solid var(--clean-border)}}
.layer-toggle-btn{{color:var(--text-muted);font-size:0.8rem;font-weight:500;padding:2px 8px;border:1px solid var(--border);border-radius:3px;background:#f8fafc}}
.layer-content{{display:none;padding:16px 18px}}
.layer-section.open .layer-content{{display:block}}
.findings-table{{width:100%;border-collapse:collapse;margin-bottom:12px;font-size:0.85rem}}
.findings-table th{{text-align:left;padding:8px 10px;font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid var(--border);font-weight:600;background:#f8fafc}}
.findings-table td{{padding:10px;border-bottom:1px solid var(--border);vertical-align:top}}
.findings-table tr:hover td{{background:#f8fafc}}
.score-pill{{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:700;font-size:0.75rem;text-align:center}}
.score-critical{{background:var(--critical-bg);color:var(--critical);border:1px solid var(--critical-border)}}
.score-high{{background:var(--high-bg);color:var(--high);border:1px solid var(--high-border)}}
.score-medium{{background:var(--medium-bg);color:var(--medium);border:1px solid var(--medium-border)}}
.score-low{{background:var(--low-bg);color:var(--low);border:1px solid var(--low-border)}}
.score-info{{background:var(--info-bg);color:var(--info);border:1px solid var(--info-border)}}
.mitre-tag{{display:inline-block;padding:2px 6px;border-radius:3px;background:#f1f5f9;color:#0369a1;font-family:Consolas,Monaco,monospace;font-size:0.75rem;text-decoration:none;border:1px solid #e2e8f0}}
.mitre-tag:hover{{background:#e0f2fe;border-color:#bae6fd}}
.detail-code{{font-family:Consolas,Monaco,monospace;font-size:0.78rem;color:#334155;word-break:break-all}}
.data-toggle{{padding:5px 12px;border-radius:4px;border:1px solid var(--border);background:#f8fafc;color:var(--text-muted);cursor:pointer;font-size:0.75rem}}
.data-toggle:hover{{background:#f1f5f9;color:var(--text)}}
.raw-data{{display:none;margin-top:10px;padding:12px;border-radius:4px;background:#f8fafc;border:1px solid var(--border);max-height:400px;overflow:auto}}
.raw-data.visible{{display:block}}
.raw-data pre{{font-family:Consolas,Monaco,monospace;font-size:0.75rem;color:#334155;white-space:pre-wrap;word-break:break-all}}
.delta-section{{margin-bottom:20px;padding:16px;border-radius:6px;border:1px solid var(--border);background:var(--card-bg)}}
.delta-section h3{{font-size:0.95rem;font-weight:600;margin-bottom:12px}}
.delta-new{{color:var(--critical);font-size:0.85rem;margin:8px 0 4px}}
.delta-resolved{{color:var(--clean);font-size:0.85rem;margin:8px 0 4px}}
.delta-item{{padding:6px 10px;border-radius:4px;margin:4px 0;font-size:0.8rem;border:1px solid var(--border)}}
.delta-item.new-item{{background:var(--critical-bg);border-color:var(--critical-border)}}
.delta-item.resolved-item{{background:var(--clean-bg);border-color:var(--clean-border)}}
.empty-state{{text-align:center;padding:20px;color:var(--text-muted);font-size:0.85rem}}
.footer{{text-align:center;padding:24px 0;color:var(--text-light);font-size:0.75rem;border-top:1px solid var(--border);margin-top:32px}}
.skip-banner{{display:flex;align-items:center;gap:6px;padding:8px 12px;border-radius:4px;background:var(--info-bg);border:1px solid var(--info-border);margin-bottom:12px;font-size:0.8rem;color:var(--info)}}
@media(max-width:768px){{
.header{{flex-direction:column;align-items:flex-start}}
.overall-card{{flex-direction:column}}
.controls{{flex-direction:column;align-items:stretch}}
.findings-table{{display:block;overflow-x:auto}}
}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>SDec</h1>
<div class="subtitle">{_esc(now)}</div>
</div>
""")

    level_class = f"badge-{overall['overall_level'].lower()}"
    html_parts.append(f"""
<div class="overall-card">
<div class="risk-box {level_class}">
<div class="score">{overall['overall_score']}</div>
<div class="label">{overall['overall_level']}</div>
</div>
<div class="overall-stats">
<div class="stat-item"><div class="value">{overall['total_findings']}</div><div class="label">Findings</div></div>
<div class="stat-item"><div class="value" style="color:var(--critical)">{overall['critical_count']}</div><div class="label">Critical</div></div>
<div class="stat-item"><div class="value" style="color:var(--high)">{overall['high_count']}</div><div class="label">High</div></div>
<div class="stat-item"><div class="value">{len(scored_chunks)}</div><div class="label">Layers</div></div>
</div>
</div>
""")

    if delta and (delta.get("new_findings") or delta.get("resolved_findings")):
        html_parts.append('<div class="delta-section">')
        html_parts.append('<h3>Delta</h3>')
        if delta.get("new_findings"):
            html_parts.append(f'<h4 class="delta-new">+ New ({len(delta["new_findings"])})</h4>')
            for nf in delta["new_findings"]:
                f = nf["finding"]
                html_parts.append(f'<div class="delta-item new-item"><strong>{_esc(f["id"])}</strong> [{_esc(f["severity"])}] {_esc(f["title"])} — <code>{_esc(f.get("detail", ""))}</code></div>')
        if delta.get("resolved_findings"):
            html_parts.append(f'<h4 class="delta-resolved">- Resolved ({len(delta["resolved_findings"])})</h4>')
            for rf in delta["resolved_findings"]:
                f = rf["finding"]
                html_parts.append(f'<div class="delta-item resolved-item"><s>{_esc(f["id"])}</s> {_esc(f["title"])}</div>')
        html_parts.append('</div>')

    html_parts.append("""
<div class="controls">
<button class="filter-btn active" onclick="filterFindings('all')">All</button>
<button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical</button>
<button class="filter-btn" onclick="filterFindings('HIGH')">High</button>
<button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium</button>
<button class="filter-btn" onclick="filterFindings('LOW')">Low</button>
<input type="text" class="search-box" placeholder="..." oninput="searchFindings(this.value)" id="searchInput">
</div>
""")

    for lid in layer_order:
        if lid not in scored_chunks:
            continue

        chunk = scored_chunks[lid]
        summary = chunk["summary"]
        badge_class = f"badge-{summary['layer_risk'].lower()}"
        findings = chunk.get("findings", [])
        data = chunk.get("data", {})

        skipped_items = []
        for key, val in data.items():
            if isinstance(val, dict) and val.get("status") == "skipped":
                skipped_items.append((key, val.get("reason", "")))

        html_parts.append(f'<div class="layer-section" data-layer="{lid}">')
        html_parts.append(f'<div class="layer-header" onclick="toggleLayer(this)">')
        html_parts.append(f'<div class="layer-title">')
        html_parts.append(f'<h2>{_esc(chunk["layer_name"])}</h2>')
        html_parts.append(f'<div class="meta">{summary["total_findings"]} findings · Max: {summary["max_score"]}</div>')
        html_parts.append(f'</div>')
        html_parts.append(f'<span class="layer-badge {badge_class}">{summary["layer_risk"]}</span>')
        html_parts.append(f'<span class="layer-toggle-btn">View</span>')
        html_parts.append(f'</div>')
        html_parts.append(f'<div class="layer-content"><div class="layer-inner">')

        if skipped_items:
            for sk_name, sk_reason in skipped_items:
                html_parts.append(f'<div class="skip-banner"><strong>SKIPPED [{_esc(sk_name)}]</strong>: {_esc(sk_reason)}</div>')

        if not findings:
            html_parts.append('<div class="empty-state">No findings detected</div>')
        else:
            html_parts.append('<table class="findings-table">')
            html_parts.append('<thead><tr><th>ID</th><th>Score</th><th>MITRE</th><th>Title</th><th>Detail</th></tr></thead>')
            html_parts.append('<tbody>')
            for f in findings:
                score_class = f"score-{f['risk_level'].lower()}"
                mitre = f.get("mitre", "N/A")
                mitre_html = f'<a href="https://attack.mitre.org/techniques/{mitre.replace(".", "/")}" target="_blank" class="mitre-tag">{_esc(mitre)}</a>' if mitre != "N/A" else '<span class="mitre-tag">—</span>'
                detail = f.get("detail", "")

                html_parts.append(f'<tr data-risk="{f["risk_level"]}" data-search="{_esc(f["id"])} {_esc(f["title"])} {_esc(detail)} {_esc(mitre)}">')
                html_parts.append(f'<td><strong>{_esc(f["id"])}</strong></td>')
                html_parts.append(f'<td><span class="score-pill {score_class}">{f["score"]}</span></td>')
                html_parts.append(f'<td>{mitre_html}</td>')
                html_parts.append(f'<td>{_esc(f["title"])}</td>')
                html_parts.append(f'<td class="detail-code">{_esc(detail)}</td>')
                html_parts.append(f'</tr>')

            html_parts.append('</tbody></table>')

        data_id = f"data-{lid}"
        data_json = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        if len(data_json) > 50000:
            data_json = data_json[:50000] + "\n... (truncated)"

        html_parts.append(f'<button class="data-toggle" onclick="toggleData(\'{data_id}\')">Raw Data</button>')
        html_parts.append(f'<div class="raw-data" id="{data_id}"><pre>{_esc(data_json)}</pre></div>')

        html_parts.append('</div></div></div>')

    html_parts.append(f"""
<div class="footer">
SDec — {_esc(now)}
</div>
</div>

<script>
function toggleLayer(header) {{
    const section = header.parentElement;
    section.classList.toggle('open');
}}

function toggleData(id) {{
    const el = document.getElementById(id);
    el.classList.toggle('visible');
}}

function filterFindings(level) {{
    const btns = document.querySelectorAll('.filter-btn');
    btns.forEach(b => {{
        b.classList.remove('active', 'active-critical', 'active-high', 'active-medium', 'active-low');
    }});
    event.target.classList.add('active');
    if (level !== 'all') {{
        event.target.classList.add('active-' + level.toLowerCase());
    }}

    const rows = document.querySelectorAll('.findings-table tbody tr');
    rows.forEach(row => {{
        if (level === 'all' || row.dataset.risk === level) {{
            row.style.display = '';
        }} else {{
            row.style.display = 'none';
        }}
    }});
}}

function searchFindings(query) {{
    const q = query.toLowerCase();
    const rows = document.querySelectorAll('.findings-table tbody tr');
    rows.forEach(row => {{
        const text = (row.dataset.search || '').toLowerCase();
        row.style.display = text.includes(q) ? '' : 'none';
    }});
}}

document.addEventListener('DOMContentLoaded', function() {{
    const sections = document.querySelectorAll('.layer-section');
    sections.forEach(s => {{
        const badge = s.querySelector('.layer-badge');
        if (badge && (badge.classList.contains('badge-critical') || badge.classList.contains('badge-high'))) {{
            s.classList.add('open');
        }}
    }});
}});
</script>
</body>
</html>""")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("".join(html_parts))
