import json
import sys
from collections import deque
from rich.console import Console
console = Console()

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    console.print("[red]\n" + "="*60)
    console.print(f"[red][!!!] [green]{severity}[/green] Alert: Potential [green][{alert_type}][/green] vulnerability detected!")
    console.print(f"[red]      - Process ID: [green]{pid}")
    console.print(f"[red]      - Alert Line: [green]{line_num}")
    console.print(f"[red]      - Evidence: {evidence}")
    console.print(f"[red]      - Full Log Entry: {json.dumps(full_log_dict)}")
    console.print("[red]="*60)

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
    if not found: console.print("[blue]No specific threats detected.")


def main():
    print("--- Starting Information Leakage Analysis... ---")
    analyze_info_leak(sys.argv[1] if len(sys.argv) > 1 else "log.jsonl", 10, 10, 16)
    print("--- Information Leakage Analysis Completed ---\n")

if __name__ == '__main__':
    main()