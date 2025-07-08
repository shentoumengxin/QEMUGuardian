import json
import sys

def analyze_race_condition_dirty_cow():
    time_window_seconds = 2
    madvise_thresh = 5
    write_thresh = 5
    
    counts_in_window = {}
    alerted_windows = set() 

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            log = json.loads(line)
            pid = log.get('pid')
            ts = log.get('ts', 0.0)
            window_key = int(ts / time_window_seconds)
            madvise_count = counts_in_window.get(window_key, 0)
            write_count = counts_in_window.get(window_key, 0)

            if log.get('event') == 'MADVISE' and log.get('advice') == 'MADV_DONTNEED':
                counts_in_window[window_key] = madvise_count + 1
            if log.get('event') == 'WRITE' and log.get('filename') == '/proc/self/mem':
                counts_in_window[window_key] = write_count + 1
            if madvise_count >= madvise_thresh and write_count >= write_thresh and window_key not in alerted_windows:
                results = {
                    "level": 8,
                    "description": "High",
                    "evidence": f"Detected {madvise_count} MADV_DONTNEED calls and {write_count} writes to /proc/self/mem in {time_window_seconds} seconds",
                    "pid": pid,
                }
                print(json.dumps(results))
                alerted_windows.add(window_key)

        except json.JSONDecodeError:
            results = {
                "level": -1,
                "description": f"Invalid JSON input: {line}",
                "pid": None,
            }
            print(json.dumps(results))

if __name__ == '__main__':
    analyze_race_condition_dirty_cow()