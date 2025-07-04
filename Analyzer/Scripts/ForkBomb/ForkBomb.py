import json

def print_alert(severity, alert_type, line_num, evidence, full_log):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {full_log}")
    print("="*60)

def analyze_fork_bomb(log_path, time_window_seconds=2, fork_threshold=50):
    print(f"\n--- 开始分析 [Fork炸弹] (窗口: {time_window_seconds}s, 阈值: {fork_threshold} forks) ---")
    found = False
    
    # 字典用于存储每个时间窗口的fork计数
    # key: 时间窗口的起始时间戳, value: 该窗口内的fork数量
    fork_counts_in_window = {}
    alerted_windows = set() # 记录已经报过警的窗口，避免重复报警

    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                
                # 我们只关心 TRACK_FORK 事件
                if log.get('event') == 'TRACK_FORK':
                    ts = log.get('ts', 0.0)
                    
                    # 计算当前时间戳属于哪个时间窗口
                    window_key = int(ts / time_window_seconds)
                    
                    # 增加该窗口的fork计数
                    current_count = fork_counts_in_window.get(window_key, 0) + 1
                    fork_counts_in_window[window_key] = current_count
                    
                    # 检查是否超过阈值，并且该窗口还未报过警
                    if current_count > fork_threshold and window_key not in alerted_windows:
                        print_alert(
                            severity="高危",
                            alert_type="资源耗尽 (Fork Bomb)",
                            line_num=line_num,
                            evidence=f"在 {time_window_seconds} 秒内检测到 {current_count} 次 fork/clone 调用，超过阈值 {fork_threshold}",
                            full_log=log
                        )
                        found = True
                        alerted_windows.add(window_key) # 标记此窗口已报警

            except (json.JSONDecodeError, TypeError):
                continue
    if not found: print("未发现明确特征。")

if __name__ == '__main__':
    analyze_fork_bomb("fork_bomb_trace.jsonl", time_window_seconds=2, fork_threshold=50)