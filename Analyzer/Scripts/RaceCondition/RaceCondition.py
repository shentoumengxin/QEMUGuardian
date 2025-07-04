import json
from collections import deque

def print_alert(severity, alert_type, line_num, evidence, full_log):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {full_log}")
    print("="*60)

def analyze_race_condition_dirty_cow(log_path, window_size=20, madvise_thresh=5, write_thresh=5):
    print(f"\n--- 开始分析 [竞争条件-Dirty COW] (窗口: {window_size}行) ---")
    print("[*] 注意：此脚本检测高频的 MADVISE 和对 /proc/self/mem 的 WRITE。")
    found = False
    syscall_window = deque(maxlen=window_size)
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                syscall_window.append(log)

                if len(syscall_window) == window_size:
                    madvise_count = sum(1 for call in syscall_window if call.get('event') == 'MADVISE' and call.get('advice') == 'MADV_DONTNEED')
                    write_count = sum(1 for call in syscall_window if call.get('event') == 'WRITE' and call.get('filename') == '/proc/self/mem')

                    if madvise_count >= madvise_thresh and write_count >= write_thresh:
                        print_alert("高危", "竞争条件 (Dirty COW-like)", line_num, f"窗口内检测到 {madvise_count}次madvise和{write_count}次对/proc/self/mem的写操作", log)
                        found = True
                        syscall_window.clear() # 清空窗口避免重复报警
            except json.JSONDecodeError:
                continue
    if not found: print("未发现明确特征。")

if __name__ == '__main__':
    analyze_race_condition_dirty_cow("race_condition_dirty_cow_trace.jsonl")