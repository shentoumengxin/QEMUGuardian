#!/usr/bin/env python3
import json
import sys

SUSPICIOUS_COMMANDS = {
    "/bin/sh", "/bin/bash", "/bin/csh", "/usr/bin/sh", "/usr/bin/bash", "sh", "bash",
}

def analyze_command_injection():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            log = json.loads(line)
            pid = log.get('pid')
            filename = log.get('filename')
            event = log.get('event')
            if event == 'EXEC' and filename in SUSPICIOUS_COMMANDS:
                result = {
                    "level": 8,
                    "description": "Potential Command Injection",
                    "pid": pid,
                    "evidence": f"Suspicious shell executed: {filename}"
                }
                print(json.dumps(result))
        except json.JSONDecodeError:
            result = {
                "level": -1,
                "description": f"Invalid JSON input: {line}",
                "pid": None
            }
            print(json.dumps(result))

if __name__ == '__main__':
    analyze_command_injection()