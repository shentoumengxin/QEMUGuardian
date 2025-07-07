import json
import sys
from rich.console import Console

SUSPICIOUS_COMMANDS = {
    "/bin/sh",
    "/bin/bash",
    "/bin/csh",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "sh",
    "bash",
}

console = Console()

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    console.print("[red]\n" + "="*60)
    console.print(f"[red][!!!] [green]{severity}[/green] Alert: Potential [green][{alert_type}][/green] vulnerability detected!")
    console.print(f"[red]      - Process ID: [green]{pid}")
    console.print(f"[red]      - Alert Line: [green]{line_num}")
    console.print(f"[red]      - Evidence: {evidence}")
    console.print(f"[red]      - Full Log Entry: {json.dumps(full_log_dict)}")
    console.print("[red]="*60)

def analyze_command_injection(log_path):
    found = False
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                pid = log.get('pid')

                if log.get('event') == 'EXEC' and log.get('filename') in SUSPICIOUS_COMMANDS:
                    print_alert("High Risk", "Command Injection", line_num, f"Suspicious shell executed: {log['filename']}", log, pid)
                    found = True
            except json.JSONDecodeError: continue
    if not found: console.print("[blue]No specific threats detected.")

def main():
    print("--- Starting Command Injection Analysis... ---")
    analyze_command_injection(sys.argv[1] if len(sys.argv) > 1 else "log.jsonl")
    print("--- Command Injection Analysis Completed ---\n")

if __name__ == '__main__':
    main()