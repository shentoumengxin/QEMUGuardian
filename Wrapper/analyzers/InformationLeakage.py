import json
import sys
import os
from collections import deque

# 状态文件的路径
STATE_FILE = '/tmp/information_leakage.state.json'
WINDOW_SIZE = 10  # 保持窗口大小一致

def load_state():
    """从文件加载状态。"""
    if not os.path.exists(STATE_FILE):
        return {
            'recvs': deque(maxlen=WINDOW_SIZE),
            'reads': deque(maxlen=WINDOW_SIZE)
        }
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            # 从list恢复deque
            return {
                'recvs': deque(data.get('recvs', []), maxlen=WINDOW_SIZE),
                'reads': deque(data.get('reads', []), maxlen=WINDOW_SIZE)
            }
    except (json.JSONDecodeError, IOError):
        return {
            'recvs': deque(maxlen=WINDOW_SIZE),
            'reads': deque(maxlen=WINDOW_SIZE)
        }

def save_state(recvs, reads):
    """将当前状态保存到文件。"""
    with open(STATE_FILE, 'w') as f:
        # 将deque转为list以便JSON序列化
        serializable_state = {
            'recvs': list(recvs),
            'reads': list(reads)
        }
        json.dump(serializable_state, f)

def analyze_info_leak():
    factor = 10
    threshold = 16

    state = load_state()
    recent_recvs = state['recvs']
    recent_reads = state['reads']

    line = sys.stdin.read().strip()
    # for line in sys.stdin:
    if not line:
        return
        # continue
    try:
        log = json.loads(line)
        event = log.get('event')
        pid = log.get('pid')

        if event == 'RECVFROM':
            recent_recvs.append({'size': log.get('size', 0), 'line_num': None})
        elif event == 'SENDTO':
            send_len = log.get('len', 0)
            if send_len > threshold:
                for recv_info in reversed(recent_recvs):
                    if send_len > recv_info['size'] * factor:
                        results = {                                
                            "level": 6.9,
                            "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
                            "description": "High Risk: Network Information Leak",
                            "pid": pid,
                            "evidence": f"Large send (len={send_len}) on this line, following small receive (size={recv_info['size']}) on line {recv_info['line_num']}",
                        }
                        print(json.dumps(results))
                        break

        elif event == 'READ':
            read_size = len(log.get('buf', ''))
            recent_reads.append({'size': read_size, 'line_num': None})
        elif event == 'WRITE':
            write_size = len(log.get('buf', ''))
            if write_size > threshold:
                for read_info in reversed(recent_reads):
                    if write_size > read_info['size'] * factor:
                        results = {
                            "level": 7.1,
                            "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
                            "description": "High Risk: File I/O Information Leak",
                            "pid": pid,
                            "evidence": f"Large write (size={write_size}) on this line, following small read (size={read_info['size']}) on line {read_info['line_num']}",
                        }
                        print(json.dumps(results))
                        break
    except json.JSONDecodeError:
        results = {
            "level": -1,
            "description": f"Invalid JSON input: {line}",
            "pid": None,
        }
        print(json.dumps(results))

    save_state(recent_recvs, recent_reads)

if __name__ == '__main__':
    analyze_info_leak()