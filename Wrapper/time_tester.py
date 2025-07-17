import subprocess
import time
import argparse
import sys
import os
from statistics import mean, stdev

def measure_average_time(command_list, command_name, num_runs):
    """
    重复执行一个给定的命令N次，并计算平均运行时间。

    :param command_list: 一个包含命令及其参数的列表。
    :param command_name: 用于在输出中标识该命令的名称。
    :param num_runs: 执行的次数。
    :return: 平均执行时间（秒），如果任何一次运行失败则返回 None。
    """
    print(f"[*] 正在测量: {command_name} (共 {num_runs} 轮)")
    durations = []

    for i in range(num_runs):
        try:
            print(f"  -> 第 {i + 1}/{num_runs} 轮...", end='', flush=True)
            start_time = time.perf_counter()
            
            subprocess.run(
                command_list,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            end_time = time.perf_counter()
            duration = end_time - start_time
            durations.append(duration)
            print(f" 完成，耗时: {duration:.4f} 秒")

        except FileNotFoundError:
            print(f"\n[!] 错误: 命令 '{command_list[0]}' 未找到。请确保它已安装并且在您的 PATH 中。", file=sys.stderr)
            return None
        except subprocess.CalledProcessError as e:
            print(f"\n[!] 错误: 命令 '{' '.join(command_list)}' 执行失败，返回码: {e.returncode}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"\n[!] 执行期间发生未知错误: {e}", file=sys.stderr)
            return None

    if not durations:
        return None

    average_time = mean(durations)
    # 计算标准差，了解数据的稳定性
    std_deviation = stdev(durations) if len(durations) > 1 else 0.0

    print(f"[+] {command_name} 完成，平均耗时: {average_time:.4f} 秒 (标准差: {std_deviation:.4f})\n")
    return average_time

def main():
    """
    主函数，用于解析参数和编排测量流程。
    """
    parser = argparse.ArgumentParser(
        description="比较一个可执行程序在无追踪、strace追踪和monitor.bt追踪下的运行时间。",
        epilog="注意: 由于bpftrace需要root权限，请使用 'sudo' 运行此脚本。"
    )
    parser.add_argument("executable", help="需要被追踪和分析的可执行程序的路径。")
    parser.add_argument(
        "-n", "--runs", 
        type=int, 
        default=10, 
        help="指定每个命令执行的次数以计算平均值 (默认: 10)"
    )
    args = parser.parse_args()

    executable_path = args.executable
    num_runs = args.runs

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
    baseline_time = measure_average_time(baseline_command, "无追踪 (Baseline)", num_runs)

    # 2. strace 测试
    # 使用 -o /dev/null 来将 strace 的大量输出重定向，最大限度减少I/O对计时影响
    strace_command = ["strace", "-o", "/dev/null", executable_path]
    strace_time = measure_average_time(strace_command, "strace 追踪", num_runs)

    # 3. bpftrace (monitor.bt) 测试
    # bpftrace 使用 -c 参数来指定要执行的命令
    # 注意: bpftrace 通常需要 sudo 权限
    bpftrace_command = ["qemu-x86_64", executable_path]
    bpftrace_time = measure_average_time(bpftrace_command, "monitor.bt (bpftrace) 追踪", num_runs)

    bpftrace_riscv_command = ["qemu-riscv64", executable_path+"_riscv64"]
    bpftrace_riscv_time = measure_average_time(bpftrace_riscv_command, "monitor.bt (bpftrace) 追踪 RISC-V", num_runs)

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
    if bpftrace_riscv_time is not None:
        print(f"monitor.bt RISC-V 耗时: {bpftrace_riscv_time:.4f} 秒")
        if baseline_time is not None:
            overhead = (bpftrace_riscv_time - baseline_time) / baseline_time * 100
            print(f"  -> 开销: ~{overhead:.2f}%")
    
    print("--------------------")

if __name__ == "__main__":
    main()