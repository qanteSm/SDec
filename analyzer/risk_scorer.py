SEVERITY_SCORES = {
    "HIGH": 85,
    "MEDIUM": 55,
    "LOW": 30,
    "INFO": 10,
}

MITRE_WEIGHT = {
    "T1542": 1.3,
    "T1014": 1.3,
    "T1547.001": 1.2,
    "T1547.004": 1.3,
    "T1546.003": 1.2,
    "T1546.008": 1.4,
    "T1546.009": 1.3,
    "T1546.010": 1.2,
    "T1546.012": 1.3,
    "T1546.015": 1.2,
    "T1053.005": 1.1,
    "T1543.003": 1.2,
    "T1036.005": 1.2,
    "T1055.001": 1.3,
    "T1059": 1.1,
    "T1059.001": 1.2,
    "T1218": 1.2,
    "T1071": 1.1,
    "T1176": 1.0,
    "T1137.001": 1.0,
    "T1554": 0.8,
    "T1546.004": 1.0,
    "T1564.004": 1.0,
    "T1565.001": 1.2,
    "T1562.001": 1.4,
    "T1562.004": 1.3,
    "T1090": 1.1,
    "N/A": 0.8,
}

MITRE_DESCRIPTIONS = {
    "T1542": "Pre-OS Boot",
    "T1014": "Rootkit",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1547.004": "Winlogon Helper DLL",
    "T1546.003": "WMI Event Subscription",
    "T1546.008": "Accessibility Features",
    "T1546.009": "AppCert DLLs",
    "T1546.010": "AppInit DLLs",
    "T1546.012": "Image File Execution Options Injection",
    "T1546.015": "COM Object Hijacking",
    "T1053.005": "Scheduled Task",
    "T1543.003": "Windows Service",
    "T1036.005": "Match Legitimate Name or Location",
    "T1055.001": "DLL Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1218": "System Binary Proxy Execution",
    "T1071": "Application Layer Protocol",
    "T1176": "Browser Extensions",
    "T1137.001": "Office Template Macros",
    "T1554": "Compromise Client Software Binary",
    "T1546.004": "Unix Shell Configuration Modification",
    "T1564.004": "NTFS File Attributes",
    "T1565.001": "Stored Data Manipulation",
    "T1562.001": "Disable or Modify Tools",
    "T1562.004": "Disable or Modify System Firewall",
    "T1090": "Proxy",
}


def score_finding(finding):
    base = SEVERITY_SCORES.get(finding.get("severity", "INFO"), 10)
    mitre = finding.get("mitre", "N/A")
    weight = MITRE_WEIGHT.get(mitre, 1.0)
    score = min(100, int(base * weight))

    return {
        **finding,
        "score": score,
        "mitre_description": MITRE_DESCRIPTIONS.get(mitre, ""),
        "risk_level": (
            "CRITICAL" if score >= 85
            else "HIGH" if score >= 70
            else "MEDIUM" if score >= 45
            else "LOW" if score >= 20
            else "INFO"
        ),
    }


def score_chunk(chunk):
    findings = chunk.get("findings", [])
    scored_findings = [score_finding(f) for f in findings]
    scored_findings.sort(key=lambda x: x["score"], reverse=True)

    max_score = max((f["score"] for f in scored_findings), default=0)
    avg_score = int(sum(f["score"] for f in scored_findings) / len(scored_findings)) if scored_findings else 0

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in scored_findings:
        level = f["risk_level"]
        if level in severity_counts:
            severity_counts[level] += 1

    return {
        "chunk_id": chunk.get("chunk_id", ""),
        "layer_name": chunk.get("layer_name", ""),
        "timestamp": chunk.get("timestamp", ""),
        "status": chunk.get("status", ""),
        "sha256": chunk.get("sha256", ""),
        "data": chunk.get("data", {}),
        "findings": scored_findings,
        "summary": {
            "total_findings": len(scored_findings),
            "max_score": max_score,
            "avg_score": avg_score,
            "severity_counts": severity_counts,
            "layer_risk": (
                "CRITICAL" if max_score >= 85
                else "HIGH" if max_score >= 70
                else "MEDIUM" if max_score >= 45
                else "LOW" if max_score >= 20
                else "CLEAN"
            ),
        },
    }


def score_all_chunks(chunks):
    scored = {}
    for chunk_id, chunk_data in chunks.items():
        scored[chunk_id] = score_chunk(chunk_data)
    return scored


def compute_overall_risk(scored_chunks):
    all_findings = []
    for chunk in scored_chunks.values():
        all_findings.extend(chunk["findings"])

    if not all_findings:
        return {
            "overall_score": 0,
            "overall_level": "CLEAN",
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
        }

    max_score = max(f["score"] for f in all_findings)
    total = len(all_findings)
    critical = sum(1 for f in all_findings if f["risk_level"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["risk_level"] == "HIGH")

    if critical > 3 or max_score >= 95:
        overall = "CRITICAL"
    elif critical > 0 or high > 5:
        overall = "HIGH"
    elif high > 0:
        overall = "MEDIUM"
    elif total > 0:
        overall = "LOW"
    else:
        overall = "CLEAN"

    return {
        "overall_score": max_score,
        "overall_level": overall,
        "total_findings": total,
        "critical_count": critical,
        "high_count": high,
    }
