import json
import sys
import os
from collections import defaultdict

STATE_FILE = '/tmp/race_condition.state.json'

def load_state():
    if not os.path.exists(STATE_FILE):
        return {
            'counts': defaultdict(lambda: {'madvise': 0, 'write': 0}),
            'alerted': set()
        }
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            counts = defaultdict(lambda: {'madvise': 0, 'write': 0})
            counts.update(data.get('counts', {}))
            alerted = set(data.get('alerted', []))
            return {'counts': counts, 'alerted': alerted}
    except (json.JSONDecodeError, IOError):
        return {
            'counts': defaultdict(lambda: {'madvise': 0, 'write': 0}),
            'alerted': set()
        }

def save_state(counts, alerted):
    with open(STATE_FILE, 'w') as f:
        serializable_state = {
            'counts': dict(counts),  
            'alerted': list(alerted)
        }
        json.dump(serializable_state, f)

def analyze_race_condition_dirty_cow():
    time_window_seconds = 2
    madvise_thresh = 5
    write_thresh = 5
    
    state = load_state()
    counts_in_window = state['counts']
    alerted_windows = state['alerted']

    line = sys.stdin.read().strip()
    if not line:
        return
    try:
        log = json.loads(line)
        pid = log.get('pid')
        ts = log.get('ts', 0.0)
        window_key = int(ts / time_window_seconds)

        event_counts = counts_in_window[window_key]

        if log.get('event') == 'MADVISE' and log.get('advice') == 'MADV_DONTNEED':
            event_counts['madvise'] += 1
        elif log.get('event') == 'WRITE': 
            event_counts['write'] += 1

        if event_counts['madvise'] >= madvise_thresh and \
           event_counts['write'] >= write_thresh and \
           window_key not in alerted_windows:

            result = {
                    "level": 7.1,
                    "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H",
                    "description": "Potential Race Condition (Dirty COW)",
                    "pid": pid,
                    "evidence": f"Detected {event_counts['madvise']} MADV_DONTNEED calls and {event_counts['write']} writes to /proc/self/mem in {time_window_seconds} seconds",
            }
            print(json.dumps(result))
            alerted_windows.add(window_key)

    except (json.JSONDecodeError, TypeError):
        result = {
            "level": -1,
            "description": f"Invalid JSON input: {line}",
            "pid": None,
        }
        print(json.dumps(result))

    save_state(counts_in_window, alerted_windows)

if __name__ == '__main__':
    analyze_race_condition_dirty_cow()