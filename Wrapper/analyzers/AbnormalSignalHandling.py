import json
import sys
import os
from collections import defaultdict

STATE_FILE = '/tmp/abnormal_signal.state.json'

SUSPICIOUS_SIGNALS = {4, 5, 7, 8, 11} # SIGILL, SIGTRAP, SIGBUS, SIGFPE, SIGSEGV

def load_state():
    if not os.path.exists(STATE_FILE):
        return {'counts': defaultdict(lambda: defaultdict(int)), 'alerted': set()}
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            counts_data = data.get('counts', {})
            counts = defaultdict(lambda: defaultdict(int))
            for k, v in counts_data.items():
                counts[k] = defaultdict(int, v)
            alerted = set(data.get('alerted', []))
            return {'counts': counts, 'alerted': alerted}
    except (json.JSONDecodeError, IOError):
        return {'counts': defaultdict(lambda: defaultdict(int)), 'alerted': set()}

def save_state(counts, alerted):
    with open(STATE_FILE, 'w') as f:
        serializable_state = {
            'counts': dict(counts),
            'alerted': list(alerted)
        }
        json.dump(serializable_state, f)

def analyze_abnormal_signal_handling():
    time_window_seconds = 5
    signal_threshold = 1

    state = load_state()
    signal_counts = state['counts']
    alerted_pids_in_window = state['alerted']

    line = sys.stdin.read().strip()
    if not line:
        return
    try:
        log = json.loads(line)
        if log.get('event') == 'SIGNAL_GENERATE':
            pid = str(log.get('pid')) 
            sig = log.get('sig')
            ts = log.get('ts', 0.0)
            window_key = str(int(ts / time_window_seconds))

            if sig in SUSPICIOUS_SIGNALS:
                alert_key = f"{window_key}-{pid}"
                    
                if alert_key in alerted_pids_in_window:
                    return

                count = signal_counts[window_key][pid] + 1
                signal_counts[window_key][pid] = count

                if count >= signal_threshold:
                    result = {
                        "level": 2.0,
                        "cvss_vector": "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
                        "description": "Abnormal Signal Handling Detected",
                        "pid": pid,
                        "evidence": f"Process handled {count} typically fatal signals (last was SIG={sig}) within {time_window_seconds} seconds.",
                    }
                    print(json.dumps(result))
                    alerted_pids_in_window.add(alert_key)

    except (json.JSONDecodeError, TypeError):
        result = {
            "level": -1,
            "description": f"Invalid JSON input: {line}",
            "pid": None,
        }
        print(json.dumps(result))
        
    save_state(signal_counts, alerted_pids_in_window)

if __name__ == '__main__':
    analyze_abnormal_signal_handling()