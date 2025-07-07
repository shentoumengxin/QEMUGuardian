import json 
import sys
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

def analyze_memory_corruption(log_path, max_pages_threshold=1000):
    found = False
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                pid = log.get('pid')
                
                if log.get('event') == 'MPROTECT':
                    if log.get('exec') == 1:
                        print_alert("High Risk", "Memory Corruption (Shellcode)", line_num, "Detected 'mprotect' call setting executable permissions (PROT_EXEC)", log, pid)
                        found = True

                elif log.get('evt') == 'MMAP_SUM':
                    max_pages = log.get('meta', {}).get('max_pages', 0)
                    if max_pages > max_pages_threshold:
                        print_alert("Medium Risk", "Memory Corruption (Weak Signal)", line_num, f"Detected abnormally large page allocation via mmap: {max_pages} pages", log, pid)
                        found = True

            except json.JSONDecodeError:
                continue
    if not found: console.print("[blue]No specific threats detected.")

def main():
    print("--- Starting Memory Corruption Analysis... ---")
    analyze_memory_corruption(sys.argv[1] if len(sys.argv) > 1 else "log.jsonl")
    print("--- Memory Corruption Analysis Completed ---\n")

if __name__ == '__main__':
    main()