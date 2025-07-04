import json 

def print_alert(severity, alert_type, line_num, evidence, full_log):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {full_log}")
    print("="*60)

def analyze_memory_corruption(log_path, max_pages_threshold=1000):
    print("\n--- 开始分析 [内存损坏利用] ---")
    print(f"[*] 注意：此脚本现同时检测 MPROTECT(强特征) 和 MMAP_SUM(弱特征)。")
    found = False
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                
                # 强特征检测: 寻找设置了可执行权限的 mprotect 调用
                if log.get('event') == 'MPROTECT':
                    if 'PROT_EXEC' in log.get('perms', ''):
                        print_alert("高危", "内存损坏利用 (Shellcode)", line_num, "检测到 'mprotect' 调用并设置了可执行权限 (PROT_EXEC)", log)
                        found = True

                # 弱特征检测: 寻找异常大的内存映射
                elif log.get('evt') == 'MMAP_SUM':
                    max_pages = log.get('meta', {}).get('max_pages', 0)
                    if max_pages > max_pages_threshold:
                        print_alert("中危", "内存损坏利用(弱特征)", line_num, f"检测到单次mmap分配了异常大的页面数: {max_pages}", log)
                        found = True

            except json.JSONDecodeError:
                continue
    if not found: print("未发现明确特征。")

if __name__ == '__main__':
    analyze_memory_corruption("memory_corruption_trace.jsonl")