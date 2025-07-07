#!/usr/bin/env python3
import subprocess
import json
import os
import argparse
import signal
from concurrent.futures import ThreadPoolExecutor
import re
# Analyzer folder path
ANALYZER_DIR = "./analyzers"

# Vulnerability level threshold (e.g., >= 8 is high-risk)
HIGH_VULNERABILITY_THRESHOLD = 8

# Map event types to analyzer scripts
EVENT_ANALYZER_MAP = {
    "EXEC": [
        "./analyzers/code_injection_analyzer.py",
        "./analyzers/exec_analyzer.py"  # Added second analyzer for EXEC
    ],
    "SOCKET": ["./analyzers/network_analyzer.py"],
    "READ": [
        "./analyzers/file_access_analyzer.py",
        "./analyzers/data_leak_analyzer.py"  # Added second analyzer for READ
    ],
    "WRITE": ["./analyzers/file_access_analyzer.py"]

}

def run_analyzer(analyzer_script, data):
    """Run an individual analyzer script and return its result."""
    try:
        result = subprocess.run(
            ['python3', analyzer_script],
            input=json.dumps(data),
            text=True,
            capture_output=True,
            timeout=5
        )
        output = result.stdout.strip()
        if not output:
            return
        result_dict = json.loads(output)
        result_dict["analyzer"] = analyzer_script
        if result.stderr:
            print(f"Analyzer stderr ({analyzer_script}): {result.stderr}")
        return result_dict
    except json.JSONDecodeError as e:
        return {"level": -1, "description": f"Analyzer JSON error: {str(e)}", "analyzer": analyzer_script}
    except subprocess.TimeoutExpired:
        return {"level": -1, "description": f"Analyzer {analyzer_script} timed out", "analyzer": analyzer_script}
    except Exception as e:
        return {"level": -1, "description": f"Error: {str(e)}", "analyzer": analyzer_script}

def generate_report(results):
    """Generate a report and handle high-risk vulnerabilities."""
    report = ["Vulnerability Report"]
    report.append("-" * 20)
    
    high_risk_pids = []
    results = [r for r in results if r is not None]
    for result in results:
        level = result.get("level", 0)
        desc = result.get("description", "No description")
        analyzer = result.get("analyzer", "Unknown")
        pid = result.get("pid")
        report.append(f"Analyzer: {analyzer}")
        report.append(f"Level: {level}")
        report.append(f"Description: {desc}")
        if pid:
            report.append(f"PID: {pid}")
        report.append("-" * 20)
        
        if level >= HIGH_VULNERABILITY_THRESHOLD and pid:
            high_risk_pids.append(pid)
    
    for pid in high_risk_pids:
        try:
            os.kill(pid, signal.SIGTERM)
            report.append(f"Terminated high-risk process PID: {pid}")
        except Exception as e:
            report.append(f"Failed to terminate PID: {pid} - {str(e)}")
    
    return "\n".join(report)

def main():


    monitor_process = subprocess.Popen(
        ['bpftrace', 'monitor.bt'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8',
        errors='replace'
    )
    print("Started monitor.bt, waiting for readiness...")

   
    CONTROL_CHAR_RGX = re.compile(r'[\x00-\x1f]+')
    with ThreadPoolExecutor(max_workers=10) as executor:
        try:
            buffer = ""
            brace_count = 0

            while True:
                raw = monitor_process.stdout.readline()
                if not raw:
                    break

                if isinstance(raw, bytes):
                    chunk = raw.decode('utf-8', errors='ignore')
                else:
                    chunk = raw

                for ch in chunk:
                    if ch == "{":
                        if brace_count == 0:
                            buffer = ""
                        brace_count += 1

                    if brace_count > 0:
                        buffer += ch

                    if ch == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            line = buffer.strip()
                            buffer = ""
                            line = CONTROL_CHAR_RGX.sub('', line)
                            # 下面走原先的 JSON 解析和分发逻辑
                            try:
                                data = json.loads(line)
                                print(f"Processing JSON event: {data}")
                                if data:
                                    event_type = data.get("event")
                                    target_analyzers = EVENT_ANALYZER_MAP.get(event_type, [])
                                    if not target_analyzers:
                                        continue
                                    futures = [executor.submit(run_analyzer, script, data) 
                                            for script in target_analyzers]
                                    results = [future.result() for future in futures]
                                    report = generate_report(results)
                                    print(report)
                                    print("=" * 50)
                            except json.JSONDecodeError as e:
                                print(f"Dropping invalid JSON: {line} (Error: {str(e)})")
                                continue  # Drop the invalid JSON line

        except KeyboardInterrupt:
            monitor_process.terminate()
            print("Wrapper terminated.")

if __name__ == "__main__":
    main()