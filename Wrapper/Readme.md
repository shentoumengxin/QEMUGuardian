# QEMU Security Monitor

一个基于 BPFTrace 的安全监控系统，用于分析不同架构可执行文件的安全漏洞。

## 功能特性

- **多架构支持**：自动识别并运行 x86、ARM、MIPS、PowerPC、RISC-V 等多种架构的可执行文件
- **系统调用监控**：使用 BPFTrace 实时监控系统调用
- **漏洞分析**：模块化的分析器系统，可扩展的漏洞检测
- **资源隔离**：使用 cgroup 限制内存、CPU 和进程数
- **实时报告**：GUI 界面实时显示漏洞报告
- **批量分析**：自动扫描目录并串行分析所有可执行文件

## 系统要求

- Linux 系统（支持 BPFTrace）
- Python 3.6+
- BPFTrace
- QEMU 用户模式模拟器
- tkinter（用于 GUI，可选）
- root 权限（用于 cgroup 功能）

## 安装

1. 安装依赖：
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip bpftrace qemu-user-static python3-tk

# 安装 QEMU 用户模式模拟器
sudo apt install qemu-user qemu-user-static qemu-user-binfmt
```

2. 设置环境：
```bash
# 克隆或下载所有文件后
python3 setup.py
```

## 文件结构

```
.
├── wrapper.py      # 主监控程序
├── arch_analyzer.py         # 架构分析器
├── report_gui.py           # 报告显示窗口
├── monitor.bt              # BPFTrace 监控脚本
├── config.json             # 配置文件
├── initial.py              # 初始化脚本
├── analyzers/              # 分析器目录
│   ├── sample_analyzer.py  # 示例分析器
│   └── ...                 # 其他分析器
```

## 使用方法

### 1. 分析单个目录中的所有可执行文件

```bash
# 基本使用（不需要 root）
python3 wrapper.py /path/to/executables

# 启用 cgroup 资源限制（需要 root）
sudo python3 wrapper.py /path/to/executables --cgroup

# 自定义资源限制
sudo python3 wrapper.py /path/to/executables \
    --cgroup \
    --memory-limit 1G \
    --cpu-quota 100000 \
    --pids-max 500 \
    --timeout 30
```

### 2. 仅分析架构信息

```bash
python3 arch_analyzer.py /path/to/executables
```

## 配置文件

`config.json` 定义了事件到分析器的映射：

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

## 编写自定义分析器

分析器是独立的 Python 脚本，接收 JSON 输入并输出分析结果：

```python
#!/usr/bin/env python3
import json
import sys

def main():
    # 读取输入
    data = json.loads(sys.stdin.read())
    
    # 分析逻辑
    result = {
        "level": 0,  # 0-10 的风险等级
        "cvss_vector": "CVSS:3.0/...",  # CVSS 向量
        "description": "描述",
        "evidence": "证据",
        "pid": data.get("pid", 0)  # 可选：相关进程 ID
    }
    
    # 输出结果
    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

## 命令行参数

- `directory`: 包含可执行文件的目录路径
- `--cgroup`: 启用 cgroup 资源限制
- `--memory-limit`: 内存限制（默认: 2G）
- `--cpu-quota`: CPU 配额（默认: 200000 = 200%）
- `--pids-max`: 最大进程数（默认: 1000）
- `--fork-max`: 最大 fork 数（默认: 50）
- `--timeout`: 每个可执行文件的超时时间（默认: 60秒）

## 故障排除

1. **权限错误**：
   - cgroup 功能需要 root 权限
   - BPFTrace 也可能需要 root 权限

2. **找不到 QEMU**：
   - 确保安装了对应架构的 QEMU 用户模式模拟器
   - 检查 `qemu-<arch>-static` 是否在 PATH 中

3. **GUI 不显示**：
   - 确保安装了 python3-tk
   - 在远程连接时可能需要 X11 转发

4. **分析器不工作**：
   - 检查 config.json 中的路径是否正确
   - 确保分析器脚本有执行权限

## 安全注意事项

- 该工具设计用于在隔离环境中分析潜在的恶意软件
- 使用 cgroup 限制资源使用
- 建议在虚拟机或容器中运行
- 不要在生产系统上分析未知的可执行文件

## 扩展开发

1. **添加新的架构支持**：
   编辑 `arch_analyzer.py` 中的 `ARCH_TO_QEMU` 映射

2. **添加新的分析器**：
   - 在 `analyzers/` 目录创建新的分析器脚本
   - 更新 `config.json` 添加事件映射

3. **自定义监控事件**：
   修改 `monitor.bt` 添加新的系统调用跟踪

