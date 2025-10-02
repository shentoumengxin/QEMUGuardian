"""Docker integration helper for running target binaries inside architecture-specific containers.

This module provides a thin wrapper around the docker SDK so that the main
`wrapper.py` can stay mostly unchanged. Core responsibilities:
  * Select proper base image for target architecture (leveraging qemu-user-static/binfmt on host)
  * Launch a short‑lived container that: copies the mounted test binary to a writable /tmp,
    waits a moment (so bpftrace can attach), executes it, then sleeps briefly before exit.
  * Expose the container's host PID (the init process PID) so we can seed bpftrace's
    @monitored map via a generated script fragment.

Assumptions:
  * Host already executed:  docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
  * The docker python SDK is installed (python3-docker). If not, docker mode will be disabled.
"""
from __future__ import annotations

import os
import time
from typing import Optional, Dict, Any

try:
    import docker  # type: ignore
    _DOCKER_AVAILABLE = True
except Exception:
    _DOCKER_AVAILABLE = False

ARCH_IMAGE_MAP = {
    # elf header e_machine mappings used in arch_analyzer output
    # 62 -> x86_64, 183 -> aarch64, 40 -> arm, 8 -> mips, (fallback to ubuntu:22.04)
    "x86_64": "ubuntu:22.04",
    "aarch64": "arm64v8/ubuntu:22.04",
    "arm": "arm32v7/ubuntu:22.04",
    "mips": "mips64le/ubuntu:22.04",
    "mipsel": "mips64le/ubuntu:22.04",
    "ppc64": "ppc64le/ubuntu:22.04",
    "riscv64": "riscv64/ubuntu:22.04",
}


def arch_to_image(arch_info) -> str:
    if isinstance(arch_info, dict):
        machine = arch_info.get("machine")
        bits = arch_info.get("bits")
        if machine == 62 and bits == 64:
            return ARCH_IMAGE_MAP["x86_64"]
        if machine == 183 and bits == 64:
            return ARCH_IMAGE_MAP["aarch64"]
        if machine == 40:
            return ARCH_IMAGE_MAP["arm"]
        if machine == 8:
            return ARCH_IMAGE_MAP["mips"]
    if isinstance(arch_info, str):
        return ARCH_IMAGE_MAP.get(arch_info, "ubuntu:22.04")
    return "ubuntu:22.04"


class DockerRunner:
    def __init__(self):
        if not _DOCKER_AVAILABLE:
            raise RuntimeError("Docker SDK not available")
        self.client = docker.from_env()

    # --- Staged mode helpers -------------------------------------------------
    def start_staged_container(self, arch_info, hold_cmd: str = "sleep 3600"):
        """Start a container that just idles (holding pattern) so we can attach bpftrace
        BEFORE the target binary executes. Returns container or None."""
        image = arch_to_image(arch_info)
        try:
            container = self.client.containers.run(
                image=image,
                command=hold_cmd,
                volumes={},  # mount later if needed via exec copying (or remount at run time)
                working_dir="/tmp",
                detach=True,
                remove=False,
                tty=False,
            )
        except Exception as e:
            print(f"[DOCKER] Failed staged container start: {e}")
            return None
        # resolve PID
        pid = 0
        for _ in range(15):  # up to 3s
            time.sleep(0.2)
            try:
                container.reload()
                pid = int(container.attrs.get("State", {}).get("Pid", 0))
                if pid:
                    break
            except Exception:
                pass
        if not pid:
            print("[DOCKER] Warning: staged container PID unresolved")
        return container

    def exec_binary_in_container(self, container, host_binary_path: str, force_qemu: bool = False, arch_info=None, mount_host_dir: bool = True):
        """Exec target binary inside an already running container.
        Strategy: bind-mount host directory if not already (cannot change mounts post-run normally),
        so fallback is to copy via docker cp API if necessary.
        For simplicity we use `docker cp` if the binary not present inside.
        Returns (exit_code:int, combined_output:str)
        """
        binary_name = os.path.basename(host_binary_path)
        # Ensure file inside container at /tmp/<binary_name>
        try:
            # docker cp host_binary_path <container_id>:/tmp/<binary_name>
            os.system(f"docker cp '{host_binary_path}' {container.id}:/tmp/{binary_name}")
        except Exception as e:
            print(f"[DOCKER] docker cp failed: {e}")
            return -1, ""

        exec_cmd = f"chmod +x /tmp/{binary_name} && /tmp/{binary_name}"
        if force_qemu and arch_info:
            emulator = None
            if isinstance(arch_info, dict):
                m = arch_info.get('machine')
                if m == 62: emulator = 'qemu-x86_64'
                elif m == 183: emulator = 'qemu-aarch64'
                elif m == 40: emulator = 'qemu-arm'
                elif m == 8: emulator = 'qemu-mips64'
            if emulator:
                exec_cmd = f"chmod +x /tmp/{binary_name} && {emulator} /tmp/{binary_name}"
        try:
            spec = self.client.api.exec_create(container.id, f"/bin/sh -c '{exec_cmd}'")
            exec_id = spec.get('Id')
            output = self.client.api.exec_start(exec_id, stream=False, demux=False)
            info = self.client.api.exec_inspect(exec_id)
            exit_code = info.get('ExitCode', -1)
            decoded = output.decode('utf-8', errors='ignore') if isinstance(output, (bytes, bytearray)) else str(output)
            return exit_code, decoded
        except Exception as e:
            print(f"[DOCKER] exec failed: {e}")
            return -1, ""

    # ---- Async exec helpers for staged monitoring --------------------------
    def exec_binary_async(self, container, host_binary_path: str, force_qemu: bool = False, arch_info=None):
        """Start execution of a binary inside container without blocking.
        Returns (exec_id or None)."""
        binary_name = os.path.basename(host_binary_path)
        try:
            os.system(f"docker cp '{host_binary_path}' {container.id}:/tmp/{binary_name}")
        except Exception as e:
            print(f"[DOCKER] docker cp failed (async): {e}")
            return None
        exec_cmd = f"chmod +x /tmp/{binary_name} && /tmp/{binary_name}"
        if force_qemu and arch_info:
            emulator = None
            if isinstance(arch_info, dict):
                m = arch_info.get('machine')
                if m == 62: emulator = 'qemu-x86_64'
                elif m == 183: emulator = 'qemu-aarch64'
                elif m == 40: emulator = 'qemu-arm'
                elif m == 8: emulator = 'qemu-mips64'
            if emulator:
                exec_cmd = f"chmod +x /tmp/{binary_name} && {emulator} /tmp/{binary_name}"
        try:
            spec = self.client.api.exec_create(container.id, f"/bin/sh -c '{exec_cmd}'")
            exec_id = spec.get('Id')
            # detach start
            self.client.api.exec_start(exec_id, detach=True, stream=False)
            return exec_id
        except Exception as e:
            print(f"[DOCKER] async exec failed: {e}")
            return None

    def inspect_exec(self, exec_id: str):
        """Return (running: bool, exit_code: int|None)."""
        try:
            info = self.client.api.exec_inspect(exec_id)
            running = info.get('Running', False)
            code = None if running else info.get('ExitCode')
            return running, code
        except Exception:
            return False, None

    def run_binary(self, binary_path: str, arch_info, extra_sleep: float = 1.0) -> Optional[Dict[str, Any]]:
        """Run `binary_path` inside container. Returns dict with container, id, pid or None on failure."""
        image = arch_to_image(arch_info)
        host_dir = os.path.dirname(os.path.abspath(binary_path))
        binary_name = os.path.basename(binary_path)

        # Command logic:
        #  1. copy to /tmp (writable)
        #  2. chmod +x
        #  3. sleep <extra_sleep> so monitor can attach
        #  4. execute
        #  5. sleep 1 to keep process alive briefly after exit
        cmd = (
            f"/bin/bash -c \"cp /mnt_ro/{binary_name} /tmp/{binary_name} && chmod +x /tmp/{binary_name} "
            f"&& echo '[DOCKER] Ready: executing {binary_name}' && sleep {extra_sleep:.1f} "
            f"&& /tmp/{binary_name}; EC=$?; echo '[DOCKER] Exit code:' $EC; sleep 1; exit $EC\""
        )
        try:
            container = self.client.containers.run(
                image=image,
                command=cmd,
                volumes={host_dir: {"bind": "/mnt_ro", "mode": "ro"}},
                working_dir="/tmp",
                detach=True,
                remove=False,
                tty=False,
            )
        except Exception as e:
            print(f"[DOCKER] Failed to start container: {e}")
            return None
        # Allow docker to initialize state & wait a bit for PID
        pid = 0
        for _ in range(10):  # up to ~2s
            time.sleep(0.2)
            try:
                container.reload()
                pid = int(container.attrs.get("State", {}).get("Pid", 0))
                if pid:
                    break
            except Exception:
                pass
        if not pid:
            print("[DOCKER] Warning: container PID unresolved (monitor seeding may be incomplete)")
        return {"container": container, "id": container.id, "pid": pid, "image": image}

    def wait(self, container, timeout: int):
        try:
            res = container.wait(timeout=timeout)
            code = res.get("StatusCode")
        except Exception as e:
            print(f"[DOCKER] wait error: {e}")
            code = -1
        try:
            logs = container.logs(tail=200).decode("utf-8", errors="ignore")
        except Exception:
            logs = ""
        return code, logs

    def cleanup(self, container):
        try:
            container.remove(force=True)
            print(f"[DOCKER] Removed container {container.id[:12]}")
        except Exception:
            pass
