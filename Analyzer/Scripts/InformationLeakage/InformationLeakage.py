import json
from collections import deque

def print_alert(severity, alert_type, line_num, evidence, full_log):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 告警行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {full_log}")
    print("="*60)

def analyze_info_leak(log_path, window_size=10, factor=10, threshold=4096):
    print(f"\n--- 开始分析 [信息泄露] (窗口: {window_size}行) ---")
    print("[*] 注意：此脚本现分析 RECVFROM 和 SENDTO 事件对。")
    found = False
    recent_recvs = deque(maxlen=window_size)
    recent_reads = deque(maxlen=window_size)
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                event = log.get('event')

                # RECVFROM 事件包含 'size' 字段
                if event == 'RECVFROM':
                    recent_recvs.append({'size': log.get('size', 0), 'line_num': line_num})
                
                # SENDTO 事件包含 'len' 字段
                elif event == 'SENDTO':
                    send_len = log.get('len', 0)
                    if send_len > threshold:
                        for recv_info in reversed(recent_recvs):
                            if send_len > recv_info['size'] * factor:
                                print_alert("高危", "信息泄露", line_num, f"在第{recv_info['line_num']}行小接收(size={recv_info['size']})后，于此行大发送(len={send_len})", log)
                                found = True
                                break
                # --- 文件I/O事件处理 ---
                elif event == 'READ':
                    read_size = len(log.get('buf', ''))
                    recent_reads.append({'size': read_size, 'line_num': line_num})

                elif event == 'WRITE':
                    write_size = len(log.get('buf', ''))
                    if write_size > threshold:
                        for read_info in reversed(recent_reads):
                            if write_size > read_info['size'] * factor:
                                print_alert("高危", "文件I/O信息泄露", line_num, f"在第{read_info['line_num']}行小读(size={read_info['size']})后，于此行大写(size={write_size})", log)
                                found = True
                                break
            except json.JSONDecodeError: continue
    if not found: print("未发现明确特征。")

if __name__ == '__main__':
    analyze_info_leak("info_leak_trace.jsonl")
