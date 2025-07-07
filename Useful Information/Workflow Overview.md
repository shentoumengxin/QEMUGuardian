### Workflow Overview

This workflow is designed for real-time security monitoring and response, combining the strengths of eBPF and Python. Here’s how it works:

1. eBPF Script Output
   - Monitors system behavior (e.g., system calls, network activity) and generates a real-time data stream.
   - **Why it’s good**: Runs in the kernel with minimal overhead, perfect for capturing events quickly.
2. Python Wrapper
   - Captures the eBPF output and processes it initially.
   - **Why it’s useful**: Python is flexible and easy to work with, but it may slow down under heavy load.
3. Parallel Analyzer
   - Analyzes the data stream to spot illegal or suspicious behavior.
   - **Why it’s strong**: Parallel processing speeds up analysis, especially with lots of data.
4. Signal Mechanism
   - Sends a lightweight signal to trigger action when something bad is detected.
   - **Why it’s fast**: Simple and quick, though it must be reliable.
5. Killer or 
   - Terminates the malicious process based on the signal.
   - **Why it works**: Stops threats fast once identified.

TO DO:

1. We need to classify the vulnerabilities into a level through the analyzer(1-8)
2. Using OverlayFS to isolate the host file system

```scss
       ┌──────────────────┐
       │  merged (挂载点) │
       └──────────────────┘
            ▲       ▲
   (read)   │       │   (write,delete）  
            │       │
    ┌───────┴───────┴───────┐
    │   OverlayFS 文件系统    │
    └───────┬───────┬───────┘
   lowerdir  │   upperdir
(read only)  │ (write)
             └── workdir （OverlayFS working dir）

```

