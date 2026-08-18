import json
import hashlib
import os
import sys
import subprocess
import time
import datetime
import concurrent.futures
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
COLLECTORS_DIR = BASE_DIR / "collectors"
CHUNKS_DIR = BASE_DIR / "chunks"
REPORTS_DIR = BASE_DIR / "reports"
BASELINES_DIR = BASE_DIR / "baselines"
CONFIG_PATH = BASE_DIR / "config.json"

LAYER_MAP = {
    "hardware": "01_hardware.ps1",
    "boot": "02_boot.ps1",
    "memory": "03_memory.ps1",
    "persistence": "04_persistence.ps1",
    "filesystem": "05_filesystem.ps1",
    "application": "06_application.ps1",
    "optimization": "07_optimization.ps1",
    "network": "08_network.ps1",
}


def load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "layers": {k: True for k in LAYER_MAP},
        "output_format": "html",
        "require_admin": False,
        "timeout_seconds": 60,
        "parallel_collectors": True,
        "baseline": {"enabled": False, "snapshot_path": "baselines/"},
        "language": "tr",
    }


def run_collector(script_name, timeout):
    script_path = COLLECTORS_DIR / script_name
    if not script_path.exists():
        return {"status": "error", "detail": f"script_not_found|{script_name}"}

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(script_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(COLLECTORS_DIR),
        )

        chunk_name = f"chunk_{script_name.replace('.ps1', '.json')}"
        chunk_path = CHUNKS_DIR / chunk_name

        if chunk_path.exists():
            with open(chunk_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            content = chunk_path.read_bytes()
            data["sha256"] = hashlib.sha256(content).hexdigest()

            with open(chunk_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            return {"status": "ok", "chunk": chunk_name, "data": data}
        else:
            return {
                "status": "error",
                "detail": f"chunk_not_created|{chunk_name}",
                "stderr": result.stderr[:500] if result.stderr else "",
            }

    except subprocess.TimeoutExpired:
        return {"status": "timeout", "detail": f"timeout|{script_name}|{timeout}s"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


def run_all_collectors(config):
    active_layers = {k: v for k, v in config["layers"].items() if v}
    timeout = config.get("timeout_seconds", 60)
    parallel = config.get("parallel_collectors", True)
    results = {}

    CHUNKS_DIR.mkdir(exist_ok=True)

    scripts = []
    for layer_name, enabled in active_layers.items():
        if layer_name in LAYER_MAP:
            scripts.append((layer_name, LAYER_MAP[layer_name]))

    if parallel:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_map = {}
            for layer_name, script_name in scripts:
                future = executor.submit(run_collector, script_name, timeout)
                future_map[future] = layer_name
                print(f"  [{layer_name}] ...", flush=True)

            for future in concurrent.futures.as_completed(future_map):
                layer_name = future_map[future]
                try:
                    results[layer_name] = future.result()
                    status = results[layer_name]["status"]
                    print(f"  [{layer_name}] {status}", flush=True)
                except Exception as e:
                    results[layer_name] = {"status": "error", "detail": str(e)}
                    print(f"  [{layer_name}] ERROR: {e}", flush=True)
    else:
        for layer_name, script_name in scripts:
            print(f"  [{layer_name}] ...", flush=True)
            results[layer_name] = run_collector(script_name, timeout)
            print(f"  [{layer_name}] {results[layer_name]['status']}", flush=True)

    return results


def load_chunks():
    chunks = {}
    if not CHUNKS_DIR.exists():
        return chunks

    for chunk_file in sorted(CHUNKS_DIR.glob("chunk_*.json")):
        try:
            with open(chunk_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            chunks[data.get("chunk_id", chunk_file.stem)] = data
        except Exception:
            pass

    return chunks


def save_baseline(chunks):
    BASELINES_DIR.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    baseline_path = BASELINES_DIR / f"baseline_{timestamp}.json"

    baseline = {
        "timestamp": datetime.datetime.now().isoformat(),
        "chunks": chunks,
    }

    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, ensure_ascii=False, indent=2)

    return baseline_path


def load_latest_baseline():
    if not BASELINES_DIR.exists():
        return None

    baselines = sorted(BASELINES_DIR.glob("baseline_*.json"), reverse=True)
    if not baselines:
        return None

    with open(baselines[0], "r", encoding="utf-8") as f:
        return json.load(f)


def compute_delta(current_chunks, baseline):
    if not baseline:
        return None

    delta = {"new_findings": [], "resolved_findings": [], "changed_data": []}
    baseline_chunks = baseline.get("chunks", {})

    for chunk_id, current in current_chunks.items():
        baseline_chunk = baseline_chunks.get(chunk_id, {})
        current_findings = {f"{f['id']}|{f.get('detail', '')}" for f in current.get("findings", [])}
        baseline_findings = {f"{f['id']}|{f.get('detail', '')}" for f in baseline_chunk.get("findings", [])}

        for f_key in current_findings - baseline_findings:
            matching = [f for f in current["findings"] if f"{f['id']}|{f.get('detail', '')}" == f_key]
            if matching:
                delta["new_findings"].append({"chunk": chunk_id, "finding": matching[0]})

        for f_key in baseline_findings - current_findings:
            matching = [f for f in baseline_chunk["findings"] if f"{f['id']}|{f.get('detail', '')}" == f_key]
            if matching:
                delta["resolved_findings"].append({"chunk": chunk_id, "finding": matching[0]})

    return delta


def main():
    print("=" * 60, flush=True)
    print("  SDec", flush=True)
    print("=" * 60, flush=True)

    config = load_config()
    mode = "scan"
    output_format = config.get("output_format", "html")
    save_baseline_flag = False

    for arg in sys.argv[1:]:
        if arg == "--save-baseline":
            save_baseline_flag = True
        elif arg == "--html":
            output_format = "html"
        elif arg == "--md":
            output_format = "md"
        elif arg in ("--both", "--all"):
            output_format = "both"
        elif arg == "--analyze-only":
            mode = "analyze"

    if mode == "scan":
        print("\n> ...\n", flush=True)
        collector_results = run_all_collectors(config)

    print("\n> ...\n", flush=True)
    chunks = load_chunks()

    if not chunks:
        print("ERROR: No chunks found.", flush=True)
        sys.exit(1)

    from risk_scorer import score_all_chunks
    scored = score_all_chunks(chunks)

    delta = None
    if config.get("baseline", {}).get("enabled", False):
        baseline = load_latest_baseline()
        if baseline:
            delta = compute_delta(chunks, baseline)
            print(f"  Delta: {len(delta['new_findings'])} new, {len(delta['resolved_findings'])} resolved", flush=True)

    if save_baseline_flag:
        bp = save_baseline(chunks)
        print(f"  Baseline: {bp}", flush=True)

    REPORTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    open_target = None

    if output_format in ("html", "both"):
        from report_html import generate_html_report
        html_path = REPORTS_DIR / f"sdec_report_{timestamp}.html"
        generate_html_report(scored, delta, config, html_path)
        print(f"\n> {html_path}", flush=True)
        open_target = html_path

    if output_format in ("md", "both"):
        from report_md import generate_md_report
        md_path = REPORTS_DIR / f"sdec_report_{timestamp}.md"
        generate_md_report(scored, delta, config, md_path)
        print(f"\n> {md_path}", flush=True)
        if not open_target:
            open_target = md_path

    print("\n" + "=" * 60, flush=True)

    if open_target:
        try:
            os.startfile(str(open_target))
        except Exception:
            pass


if __name__ == "__main__":
    main()
