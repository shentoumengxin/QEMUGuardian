import subprocess
import time
import argparse
import sys
import os

def measure_time(command_list, command_name):
    """
    执行一个给定的命令并测量其运行时间。

    :param command_list: 一个包含命令及其参数的列表 (e.g., ['ls', '-l'])。
    :param command_name: 用于在输出中标识该命令的名称。
    :return: 执行时间（秒），如果命令执行失败则返回 None。
    """
    print(f"[*] 正在测量: {command_name}...")
    try:
        start_time = time.perf_counter()
        # 执行命令，并将 stdout 和 stderr 重定向，避免打印输出影响计时
        subprocess.run(
            command_list,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        end_time = time.perf_counter()
        duration = end_time - start_time
        print(f"[+] {command_name} 完成，耗时: {duration:.4f} 秒\n")
        return duration
    except FileNotFoundError:
        print(f"[!] 错误: 命令 '{command_list[0]}' 未找到。请确保它已安装并且在您的 PATH 中。", file=sys.stderr)
        return None
    except subprocess.CalledProcessError as e:
        print(f"[!] 错误: 命令 '{' '.join(command_list)}' 执行失败，返回码: {e.returncode}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[!] 执行期间发生未知错误: {e}", file=sys.stderr)
        return None

def main():
    """
    主函数，用于解析参数和编排测量流程。
    """
    parser = argparse.ArgumentParser(
        description="比较一个可执行程序在无追踪、strace追踪和monitor.bt追踪下的运行时间。",
        epilog="注意: 由于bpftrace需要root权限，请使用 'sudo' 运行此脚本。"
    )
    parser.add_argument("executable", help="需要被追踪和分析的可执行程序的路径。")
    args = parser.parse_args()

    executable_path = args.executable

    # 检查可执行文件是否存在
    if not os.path.exists(executable_path):
        print(f"[!] 错误: 找不到可执行文件 '{executable_path}'", file=sys.stderr)
        sys.exit(1)
        
    # 检查 monitor.bt 是否存在
    if not os.path.exists("monitor.bt"):
        print("[!] 错误: 'monitor.bt' 脚本未在当前目录中找到。", file=sys.stderr)
        sys.exit(1)

    print("--- 开始性能测量 ---")

    # 1. 基准测试：无追踪
    baseline_command = [executable_path]
    baseline_time = measure_time(baseline_command, "无追踪 (Baseline)")

    # 2. strace 测试
    # 使用 -o /dev/null 来将 strace 的大量输出重定向，最大限度减少I/O对计时影响
    strace_command = ["strace", "-o", "/dev/null", executable_path]
    strace_time = measure_time(strace_command, "strace 追踪")

    # 3. bpftrace (monitor.bt) 测试
    # bpftrace 使用 -c 参数来指定要执行的命令
    # 注意: bpftrace 通常需要 sudo 权限
    bpftrace_command = ["qemu-riscv64", executable_path]
    bpftrace_time = measure_time(bpftrace_command, "monitor.bt (bpftrace) 追踪")

    print("--- 测量结果总结 ---")
    if baseline_time is not None:
        print(f"基准时间:     {baseline_time:.4f} 秒")
    if strace_time is not None:
        print(f"strace 耗时:    {strace_time:.4f} 秒")
        if baseline_time is not None:
            overhead = (strace_time - baseline_time) / baseline_time * 100
            print(f"  -> 开销: ~{overhead:.2f}%")
    if bpftrace_time is not None:
        print(f"monitor.bt 耗时: {bpftrace_time:.4f} 秒")
        if baseline_time is not None:
            overhead = (bpftrace_time - baseline_time) / baseline_time * 100
            print(f"  -> 开销: ~{overhead:.2f}%")
    
    print("--------------------")

if __name__ == "__main__":
    main()