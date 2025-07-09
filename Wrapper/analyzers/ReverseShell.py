# analyzers/ReverseShell.py
import json
import sys
import os
from collections import defaultdict

# 状态文件的路径
STATE_FILE = '/tmp/reverse_shell.state.json'

def load_state():
    """从文件加载状态。"""
    if not os.path.exists(STATE_FILE):
        return defaultdict(lambda: {'connected': False})
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            # JSON加载的是普通dict，需要转换为defaultdict
            state = defaultdict(lambda: {'connected': False})
            state.update(data)
            return state
    except (json.JSONDecodeError, IOError):
        return defaultdict(lambda: {'connected': False})

def save_state(state):
    """将当前状态保存到文件。"""
    with open(STATE_FILE, 'w') as f:
        # 将defaultdict转换为普通dict进行存储
        json.dump(dict(state), f)

def analyze_reverse_shell():
    pid_state = load_state()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            log = json.loads(line)
            pid = log.get('pid')
            if not pid:
                continue

            event = log.get('event')

            if event == 'CONNECT':
                pid_state[pid]['connected'] = True

            elif event == 'DUP2':
                # 如果一个进程已经连接到外部，并且现在正在复制文件描述符
                # 到 stdin/stdout/stderr，这非常可疑。
                if pid_state[pid]['connected']:
                    newfd = log.get('newfd')
                    if newfd in {0, 1, 2}:
                        oldfd = log.get('oldfd')
                        result = {
                            "level": 9.8,
                            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                            "description": "Potential Reverse Shell Detected",
                            "pid": pid,
                            "evidence": f"Process connected to remote host and then redirected fd {oldfd} to standard I/O (fd {newfd}).",
                        }
                        print(json.dumps(result))
                        # 清理状态以防误报
                        del pid_state[pid]

        except json.JSONDecodeError:
            result = {
                "level": -1,
                "description": f"Invalid JSON input: {line}",
                "pid": None
            }
            print(json.dumps(result))
        
        save_state(pid_state)

if __name__ == '__main__':
    analyze_reverse_shell()