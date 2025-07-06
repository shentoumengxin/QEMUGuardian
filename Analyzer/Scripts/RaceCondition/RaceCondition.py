import json
from collections import deque

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    import json
    print("\n" + "="*60)
    print(f"[!!!] {severity} Alert: Potential [{alert_type}] vulnerability detected!")
    print(f"      - Process ID: {pid}")
    print(f"      - Alert Line: {line_num}")
    print(f"      - Evidence: {evidence}")
    print(f"      - Full Log Entry: {json.dumps(full_log_dict)}")
    print("="*60)

def analyze_race_condition_dirty_cow(log_path, window_size=20, madvise_thresh=5, write_thresh=5):
    found = False
    syscall_window = deque(maxlen=window_size)
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                pid = log.get('pid')
                syscall_window.append(log)

                if len(syscall_window) == window_size:
                    madvise_count = sum(1 for call in syscall_window if call.get('event') == 'MADVISE' and call.get('advice') == 'MADV_DONTNEED')
                    write_count = sum(1 for call in syscall_window if call.get('event') == 'WRITE' and call.get('filename') == '/proc/self/mem')

                    if madvise_count >= madvise_thresh and write_count >= write_thresh:
                        print_alert("High Risk", "Race Condition (Dirty COW-like)", line_num, f"Detected {madvise_count} madvise calls and {write_count} writes to /proc/self/mem within the window", log, pid)
                        found = True
                        syscall_window.clear() # 清空窗口避免重复报警
            except json.JSONDecodeError:
                continue
    if not found: print("No specific threats detected.")

if __name__ == '__main__':
    analyze_race_condition_dirty_cow("race_condition_dirty_cow_trace.jsonl")