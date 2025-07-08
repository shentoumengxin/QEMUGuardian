import json
import sys
from collections import deque

def analyze_info_leak():
    window_size = 10
    factor = 10
    threshold = 16

    recent_recvs = deque(maxlen=window_size)
    recent_reads = deque(maxlen=window_size)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
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
                            results = {                                "level": 8,
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
                                "level": 8,
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

if __name__ == '__main__':
    analyze_info_leak()