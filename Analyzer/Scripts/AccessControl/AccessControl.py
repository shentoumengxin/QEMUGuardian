import json
import sys
from rich.console import Console

PRIVILEGE_ESCALATION_EVENTS = {"SETUID", "SETGID", "SETREUID", "SETRESUID"}
SENSITIVE_FILES = {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}

console = Console()

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    console.print("[red]\n" + "="*60)
    console.print(f"[red][!!!] [green]{severity}[/green] Alert: Potential [green][{alert_type}][/green] vulnerability detected!")
    console.print(f"[red]      - Process ID: [green]{pid}")
    console.print(f"[red]      - Alert Line: [green]{line_num}")
    console.print(f"[red]      - Evidence: {evidence}")
    console.print(f"[red]      - Full Log Entry: {json.dumps(full_log_dict)}")
    console.print("[red]="*60)

def analyze_access_control(log_path):
    found = False
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                event = log.get('event')
                pid = log.get('pid')

                if event in PRIVILEGE_ESCALATION_EVENTS and log.get('uid') == 0:
                    print_alert("High Risk", "Privilege Escalation", line_num, f"'{event}' call attempts to set uid to 0 (root)", log, pid)
                    found = True
                
                if event == 'TRACK_OPENAT':
                    filename = log.get('file', '')
                    if '../' in filename:
                        print_alert("Medium Risk", "Path Traversal", line_num, "Path contains '../' sequence", log, pid)
                        found = True
                    if filename in SENSITIVE_FILES:
                        print_alert("High Risk", "Sensitive File Access", line_num, f"Attempt to access sensitive file: {filename}", log, pid)
                        found = True
            except json.JSONDecodeError: continue
    if not found: console.print("[blue]No specific threats detected.")

def main():
    print("--- Starting Access Control Analysis... ---")
    analyze_access_control(sys.argv[1] if len(sys.argv) > 1 else "log.jsonl")
    print("--- Access Control Analysis Completed ---\n")

if __name__ == '__main__':
    main()