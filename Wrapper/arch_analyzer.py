#!/usr/bin/env python3
"""
可执行文件架构分析器
分析目录中的可执行文件，识别其架构并匹配对应的 QEMU 用户模式模拟器
"""

import os
import struct
import sys
from pathlib import Path
import json

# ELF 文件头魔数
ELF_MAGIC = b'\x7fELF'

# ELF 机器类型常量 (e_machine 字段)
EM_386 = 3          # Intel 80386
EM_ARM = 40         # ARM
EM_X86_64 = 62      # AMD x86-64
EM_AARCH64 = 183    # ARM AARCH64
EM_RISCV = 243      # RISC-V
EM_LOONGARCH = 258  # LoongArch
EM_MIPS = 8         # MIPS
EM_PPC = 20         # PowerPC
EM_PPC64 = 21       # PowerPC 64-bit
EM_S390 = 22        # IBM S390
EM_SPARC = 2        # SPARC
EM_SPARCV9 = 43     # SPARC V9
EM_SH = 42          # SuperH
EM_ALPHA = 41       # Alpha
EM_PARISC = 15      # HPPA
EM_68K = 4          # Motorola 68000
EM_CRIS = 76        # Axis Communications 32-bit embedded processor
EM_MICROBLAZE = 189 # Xilinx MicroBlaze
EM_XTENSA = 94      # Tensilica Xtensa
EM_OPENRISC = 92    # OpenRISC
EM_UNICORE = 110    # UniCore
EM_HEXAGON = 164    # Hexagon
EM_NIOS2 = 113      # Altera Nios II
EM_TRICORE = 44     # Siemens TriCore
EM_RX = 173         # Renesas RX

# 架构到 QEMU 命令的映射
ARCH_TO_QEMU = {
    # x86 架构
    (EM_386, 32, 'little'): 'qemu-i386',
    (EM_X86_64, 64, 'little'): 'qemu-x86_64',
    
    # ARM 架构
    (EM_ARM, 32, 'little'): 'qemu-arm',
    (EM_ARM, 32, 'big'): 'qemu-armeb',
    (EM_AARCH64, 64, 'little'): 'qemu-aarch64',
    (EM_AARCH64, 64, 'big'): 'qemu-aarch64_be',
    
    # MIPS 架构
    (EM_MIPS, 32, 'little'): 'qemu-mipsel',
    (EM_MIPS, 32, 'big'): 'qemu-mips',
    (EM_MIPS, 64, 'little'): 'qemu-mips64el',
    (EM_MIPS, 64, 'big'): 'qemu-mips64',
    
    # PowerPC 架构
    (EM_PPC, 32, 'any'): 'qemu-ppc',
    (EM_PPC64, 64, 'little'): 'qemu-ppc64le',
    (EM_PPC64, 64, 'big'): 'qemu-ppc64',
    
    # RISC-V 架构
    (EM_RISCV, 32, 'little'): 'qemu-riscv32',
    (EM_RISCV, 64, 'little'): 'qemu-riscv64',
    
    # 其他架构
    (EM_LOONGARCH, 64, 'little'): 'qemu-loongarch64',
    (EM_S390, 64, 'big'): 'qemu-s390x',
    (EM_SPARC, 32, 'big'): 'qemu-sparc',
    (EM_SPARCV9, 64, 'big'): 'qemu-sparc64',
    (EM_SH, 32, 'little'): 'qemu-sh4',
    (EM_SH, 32, 'big'): 'qemu-sh4eb',
    (EM_ALPHA, 64, 'little'): 'qemu-alpha',
    (EM_PARISC, 32, 'big'): 'qemu-hppa',
    (EM_68K, 32, 'big'): 'qemu-m68k',
    (EM_CRIS, 32, 'little'): 'qemu-cris',
    (EM_MICROBLAZE, 32, 'big'): 'qemu-microblaze',
    (EM_MICROBLAZE, 32, 'little'): 'qemu-microblazeel',
    (EM_XTENSA, 32, 'little'): 'qemu-xtensa',
    (EM_XTENSA, 32, 'big'): 'qemu-xtensaeb',
    (EM_OPENRISC, 32, 'big'): 'qemu-or1k',
    (EM_HEXAGON, 32, 'little'): 'qemu-hexagon',
    (EM_NIOS2, 32, 'little'): 'qemu-nios2',
}

def is_executable(path):
    """检查文件是否是 ELF 可执行，且具有执行权限"""
    try:
        if not path.is_file() or not os.access(path, os.X_OK):
            return False
        with open(path, 'rb') as f:
            return f.read(4) == ELF_MAGIC
    except:
        return False


def analyze_elf(filepath):
    """解析 ELF 头，返回 bits（位宽）、endian（字节序）和 machine（架构）"""
    try:
        with open(filepath, 'rb') as f:
            elf_header = f.read(64)
            if elf_header[:4] != ELF_MAGIC:
                return None
            ei_class = elf_header[4]
            bits = 32 if ei_class == 1 else 64 if ei_class == 2 else None
            endian_flag = elf_header[5]
            endian = 'little' if endian_flag == 1 else 'big' if endian_flag == 2 else None
            fmt = '<H' if endian == 'little' else '>H'
            e_machine = struct.unpack(fmt, elf_header[18:20])[0]
            return {'bits': bits, 'endian': endian, 'machine': e_machine, 'filepath': str(filepath)}
    except Exception as e:
        print(f"Error analyzing {filepath}: {e}", file=sys.stderr)
        return None


def get_qemu_command(arch_info):
    """根据架构信息返回 QEMU 模拟器命令"""
    machine, bits, endian = arch_info['machine'], arch_info['bits'], arch_info['endian']
    # 精确匹配
    cmd = ARCH_TO_QEMU.get((machine, bits, endian))
    if cmd:
        return cmd
    # 忽略字节序
    cmd = ARCH_TO_QEMU.get((machine, bits, 'any'))
    if cmd:
        return cmd
    # ARM 默认处理
    if machine == EM_ARM and bits == 32:
        return 'qemu-arm' if endian == 'little' else 'qemu-armeb'
    return None


def analyze_directory(directory):
    """遍历目录，返回所有支持的可执行文件及其 QEMU 命令列表"""
    results = []
    directory = Path(directory)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory", file=sys.stderr)
        return results
    for filepath in directory.rglob('*'):
        if is_executable(filepath):
            info = analyze_elf(filepath)
            if info:
                cmd = get_qemu_command(info)
                if cmd:
                    results.append({'filepath': info['filepath'], 'filename': filepath.name,
                                    'architecture': {'machine': info['machine'], 'bits': info['bits'], 'endian': info['endian']},
                                    'qemu_command': cmd})
                else:
                    print(f"Warning: 无 QEMU 映射 for {filepath} (machine={info['machine']}, bits={info['bits']}, endian={info['endian']})", file=sys.stderr)
    return results


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory>", file=sys.stderr)
        sys.exit(1)
    results = analyze_directory(sys.argv[1])
    print(json.dumps(results, indent=2))
    if results:
        print(f"\nFound {len(results)} executable(s):", file=sys.stderr)
        for r in results:
            print(f"  {r['filename']} -> {r['qemu_command']}", file=sys.stderr)
    else:
        print("\nNo supported executables found.", file=sys.stderr)

if __name__ == '__main__':
    main()
