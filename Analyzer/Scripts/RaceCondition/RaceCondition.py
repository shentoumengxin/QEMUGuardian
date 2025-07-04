#
# 脚本3: 检测竞争条件迹象 (Dirty COW-like)
#
import re
import argparse
from collections import deque

# --- 规则定义 ---
WINDOW_SIZE = 20  # 分析最近20个系统调用
MADVISE_THRESHOLD = 5  # 窗口内madvise调用的最小次数
WRITE_THRESHOLD = 5    # 窗口内对 /proc/self/mem 写操作的最小次数

def print_alert(severity, alert_type, line_num, evidence, full_log):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {full_log}")
    print("="*60)

def analyze_race_condition_log(log_path):
    """分析日志，检测高频交错的、可能是竞争条件利用的系统调用。"""
    print(f"[*] 开始分析竞争条件日志文件: {log_path}")
    vulnerability_found = False
    
    log_re = re.compile(r'^QEMU\s+(\w+):\s+(.*)$')
    # 使用双端队列作为滑动窗口
    syscall_window = deque(maxlen=WINDOW_SIZE)

    try:
        with open(log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                match = log_re.search(line.strip())
                if not match:
                    continue
                
                syscall = {'name': match.group(1), 'args': match.group(2)}
                syscall_window.append(syscall)

                # 当窗口填满后开始分析
                if len(syscall_window) == WINDOW_SIZE:
                    madvise_count = 0
                    proc_mem_write_count = 0
                    
                    for call in syscall_window:
                        if call['name'] == 'madvise' and 'MADV_DONTNEED' in call['args']:
                            madvise_count += 1
                        if call['name'] == 'write' and '/proc/self/mem' in call['args']:
                            proc_mem_write_count += 1
                    
                    if madvise_count >= MADVISE_THRESHOLD and proc_mem_write_count >= WRITE_THRESHOLD:
                        print_alert(
                            severity="高危",
                            alert_type="竞争条件 (Dirty COW-like)",
                            line_num=line_num,
                            evidence=f"在最近{WINDOW_SIZE}次调用中，检测到 {madvise_count} 次 madvise 和 {proc_mem_write_count} 次对 /proc/self/mem 的写操作",
                            full_log=f"分析窗口结束于此行"
                        )
                        vulnerability_found = True
                        syscall_window.clear() # 清空窗口避免重复报警

    except FileNotFoundError:
        print(f"[!] 错误: 文件未找到 {log_path}")
        return False
        
    if not vulnerability_found:
        print("[*] 分析完成。未发现明确的竞争条件利用特征。")
        
    return vulnerability_found

def create_sample_race_condition_log():
    """创建一个模拟Dirty COW竞争条件的假日志文件"""
    dirty_cow_pattern = "QEMU madvise: 0x7f1234, 4096, MADV_DONTNEED\nQEMU write: /proc/self/mem, 'root_payload', 12\n"
    sample_data = "QEMU mmap: ...\n" + dirty_cow_pattern * 10
    log_filename = "race_condition_trace.log"
    with open(log_filename, "w") as f: f.write(sample_data.strip())
    print(f"[*] 已生成演示日志文件: {log_filename}")
    return log_filename

if __name__ == '__main__':
    default_logfile = create_sample_race_condition_log()
    parser = argparse.ArgumentParser(description="检测竞争条件利用迹象的脚本。")
    parser.add_argument("logfile", nargs='?', default=default_logfile, help="要分析的日志文件路径")
    args = parser.parse_args()
    analyze_race_condition_log(args.logfile)