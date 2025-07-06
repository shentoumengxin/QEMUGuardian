import json 

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    import json
    print("\n" + "="*60)
    print(f"[!!!] {severity} Alert: Potential [{alert_type}] vulnerability detected!")
    print(f"      - Process ID: {pid}")
    print(f"      - Alert Line: {line_num}")
    print(f"      - Evidence: {evidence}")
    print(f"      - Full Log Entry: {json.dumps(full_log_dict)}")
    print("="*60)

def analyze_memory_corruption(log_path, max_pages_threshold=1000):
    found = False
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                pid = log.get('pid')
                
                if log.get('event') == 'MPROTECT':
                    if 'PROT_EXEC' in log.get('perms', ''):
                        print_alert("High Risk", "Memory Corruption (Shellcode)", line_num, "Detected 'mprotect' call setting executable permissions (PROT_EXEC)", log, pid)
                        found = True

                elif log.get('evt') == 'MMAP_SUM':
                    max_pages = log.get('meta', {}).get('max_pages', 0)
                    if max_pages > max_pages_threshold:
                        print_alert("Medium Risk", "Memory Corruption (Weak Signal)", line_num, f"Detected abnormally large page allocation via mmap: {max_pages} pages", log, pid)
                        found = True

            except json.JSONDecodeError:
                continue
    if not found: print("No specific threats detected.")

if __name__ == '__main__':
    analyze_memory_corruption("memory_corruption_trace.jsonl")