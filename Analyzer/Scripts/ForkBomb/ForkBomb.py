import json

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    import json
    print("\n" + "="*60)
    print(f"[!!!] {severity} Alert: Potential [{alert_type}] vulnerability detected!")
    print(f"      - Process ID: {pid}")
    print(f"      - Alert Line: {line_num}")
    print(f"      - Evidence: {evidence}")
    print(f"      - Full Log Entry: {json.dumps(full_log_dict)}")
    print("="*60)

def analyze_fork_bomb(log_path, time_window_seconds=2, fork_threshold=50):
    found = False
    
    fork_counts_in_window = {}
    alerted_windows = set() 

    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                pid = log.get('pid')
                
                if log.get('event') == 'TRACK_FORK':
                    ts = log.get('ts', 0.0)
                    window_key = int(ts / time_window_seconds)
                    current_count = fork_counts_in_window.get(window_key, 0) + 1
                    fork_counts_in_window[window_key] = current_count
                    
                    if current_count > fork_threshold and window_key not in alerted_windows:
                        print_alert("High Risk", "Resource Exhaustion (Fork Bomb)", line_num, f"Detected {current_count} fork/clone calls in {time_window_seconds} seconds, exceeding threshold of {fork_threshold}", log, pid)
                        found = True
                        alerted_windows.add(window_key) # 标记此窗口已报警

            except (json.JSONDecodeError, TypeError):
                continue
    if not found: print("No specific threats detected.")

if __name__ == '__main__':
    analyze_fork_bomb("fork_bomb_trace.jsonl", time_window_seconds=2, fork_threshold=50)