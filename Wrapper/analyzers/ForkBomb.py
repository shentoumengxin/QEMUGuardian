import json
import sys

def analyze_fork_bomb():
    time_window_seconds = 2
    fork_threshold = 50
    
    fork_counts_in_window = {}
    alerted_windows = set() 

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            log = json.loads(line)
            pid = log.get('pid')
            
            if log.get('event') == 'TRACK_FORK':
                ts = log.get('ts', 0.0)
                window_key = int(ts / time_window_seconds)

                current_count = fork_counts_in_window.get(window_key, 0) + 1
                fork_counts_in_window[window_key] = current_count
                
                if current_count > fork_threshold and window_key not in alerted_windows:
                    results = {
                        "level": 8,
                        "description": "High Risk: Resource Exhaustion (Fork Bomb)",
                        "pid": pid,
                        "evidence": f"Detected {current_count} fork/clone calls in {time_window_seconds} seconds, exceeding threshold of {fork_threshold}.",
                    }
                    print(json.dumps(results))
                    alerted_windows.add(window_key) # Mark this window as alerted

        except (json.JSONDecodeError, TypeError):
            results = {
                "level": -1,
                "description": f"Invalid JSON input: {line}",
                "pid": None,
            }
            print(json.dumps(results))

if __name__ == '__main__':
    analyze_fork_bomb()