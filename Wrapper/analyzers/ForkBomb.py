import json
import sys
import os
from collections import defaultdict

# 状态文件的路径
STATE_FILE = '/tmp/fork_bomb.state.json'

def load_state():
    """从文件加载状态。如果文件不存在或为空，则返回初始状态。"""
    if not os.path.exists(STATE_FILE):
        return {'counts': defaultdict(int), 'alerted': set()}
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            # JSON不支持set，因此加载后将list转回set
            # defaultdict也需要特殊处理
            counts = defaultdict(int, data.get('counts', {}))
            alerted = set(data.get('alerted', []))
            return {'counts': counts, 'alerted': alerted}
    except (json.JSONDecodeError, IOError):
        return {'counts': defaultdict(int), 'alerted': set()}

def save_state(counts, alerted):
    """将当前状态保存到文件。"""
    with open(STATE_FILE, 'w') as f:
        # JSON不支持set，因此保存前将set转为list
        serializable_state = {
            'counts': counts,
            'alerted': list(alerted)
        }
        json.dump(serializable_state, f)


def analyze_fork_bomb():
    time_window_seconds = 2
    fork_threshold = 50

    state = load_state()
    fork_counts_in_window = state['counts']
    alerted_windows = state['alerted']

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
                        "level": 8.5,
                        "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H",
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

        save_state(fork_counts_in_window, alerted_windows)
if __name__ == '__main__':
    analyze_fork_bomb()