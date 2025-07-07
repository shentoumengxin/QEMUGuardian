import json
import sys
from rich.console import Console

console = Console()

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    console.print("[red]\n" + "="*60)
    console.print(f"[red][!!!] {severity} Alert: Potential [{alert_type}] vulnerability detected!")
    console.print(f"[red]      - Process ID: {pid}")
    console.print(f"[red]      - Alert Line: {line_num}")
    console.print(f"[red]      - Evidence: {evidence}")
    console.print(f"[red]      - Full Log Entry: {json.dumps(full_log_dict)}")
    console.print("[red]="*60)

def analyze_race_condition_dirty_cow(log_path, time_window_seconds=2, madvise_thresh=5, write_thresh=5):
    found = False
    
    counts_in_window = {}
    alerted_windows = set() 

    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                pid = log.get('pid')
                ts = log.get('ts', 0.0)
                window_key = int(ts / time_window_seconds)
                madvise_count = counts_in_window.get(window_key, 0)
                write_count = counts_in_window.get(window_key, 0)

                if log.get('event') == 'MADVISE' and log.get('advice') == 'MADV_DONTNEED':
                    counts_in_window[window_key] = madvise_count + 1
                if log.get('event') == 'WRITE' and log.get('filename') == '/proc/self/mem':
                    counts_in_window[window_key] = write_count + 1
                if madvise_count >= madvise_thresh and write_count >= write_thresh and window_key not in alerted_windows:
                    print_alert("High Risk", "Race Condition (Dirty COW-like)", line_num, f"Detected {madvise_count} madvise calls and {write_count} writes to /proc/self/mem in {time_window_seconds} seconds, exceeding threshold of ({madvise_thresh},{write_thresh}) ", log, pid)
                    found = True
                    alerted_windows.add(window_key)

            except json.JSONDecodeError:
                continue
    if not found: console.print("[blue]No specific threats detected.")

def main():
    print("--- Starting Race Condition Analysis... ---")
    analyze_race_condition_dirty_cow(sys.argv[1] if len(sys.argv) > 1 else "log.jsonl")
    print("--- Race Condition Analysis Completed ---\n")

if __name__ == '__main__':
    main()