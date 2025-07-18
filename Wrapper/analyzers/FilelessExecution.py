# analyzers/FilelessExecution.py
import json
import sys
import re

#  /proc/self/fd/.. or /proc/<pid>/fd/.. 
PROC_FD_PATH_RE = re.compile(r'/proc/(self|\d+)/fd/\d+')

def analyze_fileless_execution():
    line = sys.stdin.read().strip()
    if not line:
        return
    try:
        log = json.loads(line)
        if log.get('event') == 'EXEC':
            filename = log.get('filename', '')
            if PROC_FD_PATH_RE.match(filename):
                pid = log.get('pid')
                result = {
                    "level": 9.3,
                    "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                    "description": "Potential Fileless Execution Detected",
                    "pid": pid,
                    "evidence": f"Process executed a file from a memory file descriptor: {filename}",
                }
                print(json.dumps(result))
    except json.JSONDecodeError:
        result = {
            "level": -1,
            "description": f"Invalid JSON input: {line}",
            "pid": None,
        }
        print(json.dumps(result))

if __name__ == '__main__':
    analyze_fileless_execution()