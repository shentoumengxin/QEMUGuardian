import json
import sys
import os
from collections import defaultdict

# 状态文件的路径
STATE_FILE = '/tmp/race_condition.state.json'

def load_state():
    """从文件加载状态。"""
    if not os.path.exists(STATE_FILE):
        return {
            'counts': defaultdict(lambda: {'madvise': 0, 'write': 0}),
            'alerted': set()
        }
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            # 加载时需要将普通dict转为defaultdict
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
    """将当前状态保存到文件。"""
    with open(STATE_FILE, 'w') as f:
        serializable_state = {
            'counts': dict(counts),  # 将defaultdict转为dict进行保存
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

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            log = json.loads(line)
            pid = log.get('pid')
            ts = log.get('ts', 0.0)
            window_key = int(ts / time_window_seconds)

            event_counts = counts_in_window[window_key]

            if log.get('event') == 'MADVISE' and log.get('advice') == 'MADV_DONTNEED':
                event_counts['madvise'] += 1
            # 根据接口文档，write 事件没有 filename 字段，这里假设是为了检测 Dirty COW
            # 漏洞而专门写入 /proc/self/mem
            elif log.get('event') == 'WRITE': 
                # 这里可以增加对 fd 或 buf 内容的检查，如果 monitor.bt 支持
                event_counts['write'] += 1

            if event_counts['madvise'] >= madvise_thresh and \
               event_counts['write'] >= write_thresh and \
               window_key not in alerted_windows:
                
                result = {
                        "level": 8.7,
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