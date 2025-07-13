# QEMU Security Monitor

A security monitoring system based on BPFTrace for analyzing vulnerabilities in executables across multiple CPU architectures.

## Features

- **Multi-Architecture Support**: Automatically identifies and runs executables for x86, ARM, MIPS, PowerPC, RISC-V, and more
- **Syscall Monitoring**: Real-time system call monitoring with BPFTrace
- **Vulnerability Analysis**: Modular, extensible analyzer system for vulnerability detection
- **Resource Isolation**: Uses cgroup to limit memory, CPU, and process count
- **Real-Time Reporting**: GUI displays vulnerability reports in real time
- **Batch Analysis**: Automatically scans directories and sequentially analyzes all executables

## System Requirements

- Linux (with BPFTrace support)
- Python 3.6+
- BPFTrace
- QEMU user-mode emulator
- tkinter (optional, for GUI)
- Root privileges (for cgroup support)

## Installation

1. Install dependencies:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip bpftrace qemu-user-static python3-tk

# Install QEMU user-mode emulator
sudo apt install qemu-user qemu-user-static qemu-user-binfmt
```



## File Structure

```bash
.
├── wrapper.py            # Main monitoring program
├── arch_analyzer.py      # Architecture analyzer
├── report_gui.py         # GUI report window
├── monitor.bt            # BPFTrace monitoring script
├── config.json           # Configuration file
├── initial.py            # Initialization script
├── vulnerability_report.log #log file
├── analyzers/            # Analyzer directory
│   ├── sample_analyzers.py  # Example analyzer
│   └── ...               # Other analyzers
├── malicious/            # Analyzer directory
│   ├── sample_code.py  # Example executable files
│   └── ...               # 
├── report/            # hitorical reports
│   ├── report_session_2025.log  # Example executable files
│   └── ...               # 
```

## Usage

### 1. Analyze all executables in a directory

```bash
# Basic usage (no root required)
python3 wrapper.py /path/to/executables

# Enable cgroup resource limits (root required)
sudo python3 wrapper.py /path/to/executables --cgroup

# Custom resource limits
sudo python3 wrapper.py /path/to/executables \
    --cgroup \
    --memory-limit 1G \
    --cpu-quota 100000 \
    --pids-max 500 \
    --timeout 30
```

### 2. Analyze only architecture information

```bash
python3 arch_analyzer.py /path/to/executables
```

## Configuration File

`config.json` defines the mapping from events to analyzers:

```json
{
  "EVENT_ANALYZER_MAP": {
    "EXEC": ["./analyzers/CodeInjection.py", "./analyzers/FilelessExecution.py"],
    "SETUID": ["./analyzers/AccessControl.py"],
    "SETGID": ["./analyzers/AccessControl.py"],
    "SETREUID": ["./analyzers/AccessControl.py"],
    "SETRESUID": ["./analyzers/AccessControl.py"],
    "TRACK_OPENAT": ["./analyzers/AccessControl.py"],
    "TRACK_FORK": ["./analyzers/ForkBomb.py"],
    "READ": ["./analyzers/InformationLeakage.py"],
    "WRITE": ["./analyzers/InformationLeakage.py", "./analyzers/RaceCondition.py"],
    "RECVFROM": ["./analyzers/InformationLeakage.py"],
    "SENDTO": ["./analyzers/InformationLeakage.py"],
    "MPROTECT": ["./analyzers/MemoryCorruption.py"],
    "MADVISE": ["./analyzers/RaceCondition.py"],
    "CONNECT": ["./analyzers/ReverseShell.py"],
    "SIGNAL_GENERATE": ["./analyzers/AbnormalSignalHandling.py"],
    "READLINKAT": ["./analyzers/Reconnaissance.py"],
    "DUP2": ["./analyzers/ReverseShell.py"]
  },
  "EVT_ANALYZER_MAP": {
    "MMAP_SUM": ["./analyzers/MemoryCorruption.py"]
  }
}
```

## Writing Custom Analyzers

Analyzers are independent Python scripts that receive JSON input and output analysis results:

```python
#!/usr/bin/env python3
import json
import sys

def main():
    # Read input
    data = json.loads(sys.stdin.read())
    
    # Analysis logic
    result = {
        "level": 0,  # Risk level (0-10)
        "cvss_vector": "CVSS:3.0/...",  # CVSS vector
        "description": "Description",
        "evidence": "Evidence",
        "pid": data.get("pid", 0)  # Optional: related process ID
    }
    
    # Output result
    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

## Command-Line Arguments

- `directory`: Path to directory containing executables
- `--cgroup`: Enable cgroup resource limits
- `--memory-limit`: Memory limit (default: 2G)
- `--cpu-quota`: CPU quota (default: 200000 = 200%)
- `--pids-max`: Maximum number of processes (default: 1000)
- `--fork-max`: Maximum forks (default: 50)
- `--timeout`: Timeout per executable in seconds (default: 60)

## Troubleshooting

1. **Permission errors**:
   - cgroup requires root privileges
   - BPFTrace may also require root privileges
2. **QEMU not found**:
   - Ensure the appropriate QEMU user-mode emulator is installed
   - Check that `qemu-<arch>-static` is in your PATH
3. **GUI not displaying**:
   - Ensure python3-tk is installed
   - X11 forwarding may be needed for remote connections
4. **Analyzer not working**:
   - Check that paths in config.json are correct
   - Ensure analyzer scripts have execution permission

## Security Notes

- This tool is intended for analyzing potentially malicious software in isolated environments
- Use cgroups to limit resource usage
- It is recommended to run in a virtual machine or container
- Do **not** analyze unknown executables on production systems

## Extending the System

1. **Add new architecture support**:
    Edit the `ARCH_TO_QEMU` mapping in `arch_analyzer.py`
2. **Add new analyzers**:
   - Create new analyzer scripts in the `analyzers/` directory
   - Update `config.json` to map events to new analyzers
3. **Customize monitoring events**:
    Edit `monitor.bt` to add new system call tracepoints

------
