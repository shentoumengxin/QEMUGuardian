import json
from collections import deque

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    import json
    print("\n" + "="*60)
    print(f"[!!!] {severity} Alert: Potential [{alert_type}] vulnerability detected!")
    print(f"      - Process ID: {pid}")
    print(f"      - Alert Line: {line_num}")
    print(f"      - Evidence: {evidence}")
    print(f"      - Full Log Entry: {json.dumps(full_log_dict)}")
    print("="*60)

def analyze_info_leak(log_path, window_size=10, factor=10, threshold=4096):
    found = False
    recent_recvs = deque(maxlen=window_size)
    recent_reads = deque(maxlen=window_size)
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                event = log.get('event')
                pid = log.get('pid')

                if event == 'RECVFROM':
                    recent_recvs.append({'size': log.get('size', 0), 'line_num': line_num})
                elif event == 'SENDTO':
                    send_len = log.get('len', 0)
                    if send_len > threshold:
                        for recv_info in reversed(recent_recvs):
                            if send_len > recv_info['size'] * factor:
                                print_alert("High Risk", "Network Information Leak", line_num, f"Large send (len={send_len}) on this line, following small receive (size={recv_info['size']}) on line {recv_info['line_num']}", log, pid)
                                found = True
                                break

                elif event == 'READ':
                    read_size = len(log.get('buf', ''))
                    recent_reads.append({'size': read_size, 'line_num': line_num})
                elif event == 'WRITE':
                    write_size = len(log.get('buf', ''))
                    if write_size > threshold:
                        for read_info in reversed(recent_reads):
                            if write_size > read_info['size'] * factor:
                                print_alert("High Risk", "File I/O Information Leak", line_num, f"Large write (size={write_size}) on this line, following small read (size={read_info['size']}) on line {read_info['line_num']}", log, pid)
                                found = True
                                break
            except json.JSONDecodeError: continue
    if not found: print("No specific threats detected.")

if __name__ == '__main__':
    analyze_info_leak("info_leak_trace.jsonl")
