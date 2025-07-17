# Welcome to **qemu-guardian** 🛡️

**Qemu-guardian** is a powerful and easy-to-use security analysis toolkit for Linux executables across multiple CPU architectures. With qemu-guardian, you can quickly analyze, monitor, and assess the security risks of untrusted binaries—even if they are compiled for platforms different from your host. 🚀
![8f5b38f925978fa06394d5bbc0e125b](README.assets/8f5b38f925978fa06394d5bbc0e125b-1752689618124-3.png)

The **Wrapper** leverage eBPF to monitor QEMU-user, then distribute the captured syscalls to the analyzers for analysis.

<img src="README.assets/b2a488b6ef4ff796e3b3e715631b07b3_-1752689870453-1.png" alt="b2a488b6ef4ff796e3b3e715631b07b3_" style="zoom:56%;" />

It is a powerful and easy-to-use security analysis toolkit for Linux executables across multiple CPU architectures. With qemu-guardian, you can quickly analyze, monitor, and assess the security risks of untrusted ELF binaries—even if they are compiled for platforms different from your host. 🚀

## What Can Wrapper Do? 🤔

- **Multi-Architecture Analysis** 
   Seamlessly supports x86, ARM, MIPS, PowerPC, RISC-V, and more—automatically detecting and running each executable with the right QEMU emulator.
- **Real-Time System Call Monitoring** 
   Uses eBPF/BPFTrace to capture and analyze system call activity for each target, giving you deep behavioral insight.
- **Modular Vulnerability Detection** 
   Detects a wide range of vulnerabilities (code injection, privilege escalation, memory corruption, etc.) using extensible Python-based analyzers.
- **Resource Isolation & Sandboxing** 
   Leverages Linux cgroup for strict resource control, keeping your system safe during analysis.
- **Batch and Automated Analysis** 
   Scan and analyze an entire directory of executables in one command—no manual setup needed.
- **Real-Time Reports** 
   View security findings instantly through a convenient GUI.

> **Note:** If you are interested in this project and would like to contribute, feel free to contact us or check the README in the [`Wrapper`](./Wrapper) folder.  
> 
We welcome your help in developing new analyzers!
## Why Use qemu-guardian?

Whether you’re a security researcher, reverse engineer, or developer, **qemu-guardian** makes it easy to identify risky behavior and vulnerabilities before running untrusted code on real hardware. Analyze cross-architecture malware, firmware, or any Linux binary safely and efficiently.

------

## Get Started 🚀

**Guardian** 🛡️is a chrome plugin that can detect and isolate downloaded ELF files, upload them to a
server for wrapper analysis, and return the results.

![c2efd4444e87062d841d75359367bd4](README.assets/c2efd4444e87062d841d75359367bd4-1752689602980-1.png)

Actually, we have put **Wrapper** in my server. It's just a very simple demo-version. However, you can try to use this plugins if you don't want to set up wrapper in your computer or you are Windows users. You can go to the `ChromeExtension` Folder to get more information. 

This plugin will automatically communicate with our sever, then give you the vulnerability reports of the ELF you uploaded.

> **Note:** Our current service is quite basic.  
> **Please do not attempt to attack our servers. Legal action will be taken against any malicious activity.**



## Why Use qemu-guardian?

* **Ease of Use**: A browser extension simplifies the workflow by automating download detection and
  environment setup, offering a plug-and-play experience.
* **Extensibility**: Features a plugin-based architecture where new analyzers can be easily added through simple configuration to expand detection coverage.
* **Lightweight**: The combination of QEMU-user and eBPF ensures minimal overhead, enabling fast
  execution and real-time responsiveness.
* **Cross-Architecture and even cross platform**: Supports multiple CPUarchitectures, allowing users to analyze programs for various platforms on a single hostGet. If you use the Chrome extension, you can also test ELF binaries with your Windows or Linux systems.  



## Started 🚀

1. **Go to the  [`Wrapper`](./Wrapper) directory in this repository.**
2. **Follow the instructions in the README to install dependencies and start analyzing your executables!**
3. **If you are windows or linux user, you can go to 'ChromeExtension' to get a File Scan Interceptor and Guadian. It can detect the ELF download from your browser and send to out demo-Server automatically.**
Ready to make your analysis smarter and safer?
 **Download qemu-guardian and get started today!** ✨
