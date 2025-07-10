# analyzers/ReverseShell.py
import json
import sys
import os
from collections import defaultdict

STATE_FILE = '/tmp/reverse_shell.state.json'

def load_state():
    """从文件加载状态。"""
    if not os.path.exists(STATE_FILE):
        return defaultdict(lambda: {'connected': False})
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            state = defaultdict(lambda: {'connected': False})
            state.update(data)
            return state
    except (json.JSONDecodeError, IOError):
        return defaultdict(lambda: {'connected': False})

def save_state(state):
    """将当前状态保存到文件。"""
    with open(STATE_FILE, 'w') as f:
        json.dump(dict(state), f)

def analyze_reverse_shell():
    line = sys.stdin.read().strip()
    if not line:
        return
    try:
        log = json.loads(line)
        pid = str(log.get('pid'))
        if not pid:
            return
        event = log.get('event')
        if event == 'CONNECT':
            pid_state = load_state()
            pid_state[pid]['connected'] = True
            save_state(pid_state)
        elif event == 'DUP2':
            pid_state = load_state()
            if pid_state[pid]['connected']:
                newfd = log.get('newfd')
                if newfd in {0, 1, 2}:
                    oldfd = log.get('oldfd')
                    result = {
                        "level": 9.4,
                        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                        "description": "Potential Reverse Shell Detected",
                        "pid": pid,
                        "evidence": f"Process connected to remote host and then redirected fd {oldfd} to standard I/O (fd {newfd}).",
                    }
                    print(json.dumps(result))
                    del pid_state[pid]
                    save_state(pid_state)
    except json.JSONDecodeError:
        result = {
            "level": -1,
            "description": f"Invalid JSON input: {line}",
            "pid": None
        }
        print(json.dumps(result))

if __name__ == '__main__':
    analyze_reverse_shell()