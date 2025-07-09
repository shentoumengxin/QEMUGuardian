#!/usr/bin/env python3
import subprocess
import json
import os
import argparse
import signal
from concurrent.futures import ThreadPoolExecutor
import re
from collections import deque


seen_pids = set()       # 只追加不弹出，保留整个监控周期内见过的 PID
hidden_failures = set()    # 记录那些 kill 失败的高危 PID

# Analyzer folder path
ANALYZER_DIR = "./analyzers"

# Vulnerability level threshold (e.g., >= 8 is high-risk)
HIGH_VULNERABILITY_THRESHOLD = 5

# Map event types to analyzer scripts
EVENT_ANALYZER_MAP = {
    "EXEC": ["./analyzers/CodeInjection.py", "./analyzers/FilelessExecution.py"],
    # "EXEC": ["./analyzers/CodeInjection.py"],
    "SETUID": ["./analyzers/AccessControl.py"],
    "SETGID": ["./analyzers/AccessControl.py"],
    "SETREUID": ["./analyzers/AccessControl.py"],
    "SETRESUID": ["./analyzers/AccessControl.py"],
    "TRACK_OPENAT": ["./analyzers/AccessControl.py"],
    "TRACK_FORK": ["./analyzers/ForkBomb.py"],
    "READ": ["./analyzers/InformationLeakage.py"],
    "WRITE": [
        "./analyzers/InformationLeakage.py",
        "./analyzers/RaceCondition.py"],
    "RECVFROM": ["./analyzers/InformationLeakage.py"],
    "SENDTO": ["./analyzers/InformationLeakage.py"],
    "MPROTECT": ["./analyzers/MemoryCorruption.py"],
    "MADVISE": ["./analyzers/RaceCondition.py"],
    "CONNECT": ["./analyzers/ReverseShell.py"],
    "SIGNAL_GENERATE": ["./analyzers/AbnormalSignalHandling.py"],
    "READLINKAT": ["./analyzers/Reconnaissance.py"],
    "DUP2": ["./analyzers/ReverseShell.py"]
}

EVT_ANALYZER_MAP = {
    "MMAP_SUM": ["./analyzers/MemoryCorruption.py"],
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
def safe_terminate(pid, report_lines):
    """
    Try to terminate the given PID (and its process group).  
    Append status messages into report_lines.
    """
    # 1) Check existence by sending signal 0
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        report_lines.append(f"Process {pid} no longer exists; skipping.")
        hidden_failures.add(pid)
        return False

    # 2) Attempt to kill entire process group
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGTERM)
        report_lines.append(f"Sent SIGTERM to process group {pgid} (PID {pid}).")
        return True
    except ProcessLookupError:
        report_lines.append(f"Could not get pgid for PID {pid}; it may be hidden.")
        hidden_failures.add(pid)
        return False
    except PermissionError as e:
        report_lines.append(f"Permission denied killing PID {pid}: {e}")
        hidden_failures.add(pid)
        return False
    except Exception:
        # Fallback: record failure
        report_lines.append(f"Unknown error terminating PID {pid}.")
        hidden_failures.add(pid)
        return False

def generate_report(results):
    """Generate a report and handle high-risk vulnerabilities."""
    valid = [r for r in (results or []) if r is not None]
    # 如果过滤后列表空，就直接返回，不打印任何东西
    if not valid:
        return
    report = ["Vulnerability Report"]
    report.append("-" * 50)
    
    high_risk_pids = []
    for result in results:
        if not result:
            continue
        level = result.get("level", 0)
        cvss_vector = result.get("cvss_vector", "Unknown")
        desc = result.get("description", "No description")
        analyzer = result.get("analyzer", "Unknown")
        pid = result.get("pid")
        evidence = result.get("evidence", "No evidence")
        report.append(f"Analyzer: {analyzer}")
        report.append(f"Level: {level}")
        report.append(f"CVSS Vector: {cvss_vector}")
        report.append(f"Description: {desc}")
        if pid:
            report.append(f"PID: {pid}")
        report.append(f"Evidence: {evidence}")
        report.append("-" * 50)
        
        if level >= HIGH_VULNERABILITY_THRESHOLD and pid>0:
            high_risk_pids.append(pid)
    
    for pid in high_risk_pids:
        safe_terminate(pid, report)

    return "\n".join(report)

def main():

    isolation_asked = False
    os.system("python3 initial.py") 
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
                                # print(f"Processing JSON event: {data}")
                                if data:
                                    pid = data.get("pid")
                                    if pid:
                                        seen_pids.add(pid)
                                    event_type = data.get("event")
                                    evt_type = data.get("evt")
                                    target_analyzers = EVENT_ANALYZER_MAP.get(event_type, [])
                                    # if not target_analyzers:
                                    #     target_analyzers = EVT_ANALYZER_MAP.get(evt_type, [])
                                        # target_analyzers = []
                                    target_analyzers += EVT_ANALYZER_MAP.get(evt_type, [])
                                    if not target_analyzers:
                                        continue
                                    futures = [executor.submit(run_analyzer, script, data) 
                                            for script in target_analyzers]
                                    results = [future.result() for future in futures]
                                    if( not results):
                                        continue
                                    report = generate_report(results)
                                    if not report:
                                        continue
                                    print(report)
                                    print("=" * 50)
                                    # If any hidden failures happened, alert the user
                                    if hidden_failures and not isolation_asked:
                                        print(f"\nWARNING: could not terminate PIDs: "
                                            f"{', '.join(map(str, hidden_failures))}")
                                        confirm = input("Perform full isolation of all seen PIDs? [y/N]: ")
                                        if confirm.strip().lower() == 'y':
                                            for p in set(seen_pids):
                                                try:
                                                    pg = os.getpgid(p)
                                                    os.killpg(pg, signal.SIGTERM)
                                                    print(f"Isolated pgid {pg} (PID {p})")
                                                except Exception as e:
                                                    print(f"Failed isolate PID {p}: {e}")
                                            seen_pids.clear()
                                            hidden_failures.clear()
                                        else:
                                            print("Skipping full isolation.")
                                            hidden_failures.clear()
                                        isolation_asked = True
                            except json.JSONDecodeError as e:
                                print(f"Dropping invalid JSON: {line} (Error: {str(e)})")
                                continue  # Drop the invalid JSON line

        except KeyboardInterrupt:
            monitor_process.terminate()
            print("Wrapper terminated.")

if __name__ == "__main__":
    main()
