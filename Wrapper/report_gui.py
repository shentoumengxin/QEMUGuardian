import tkinter as tk
from tkinter import scrolledtext
import sys
import threading
import re
import datetime

class ReportWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerability Report (Live)")
        self.root.geometry("800x600")

        self.log_file_path = "vulnerability_report.log"
        
        # 创建主框架
        main_frame = tk.Frame(root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 创建状态栏
        self.status_bar = tk.Label(main_frame, text="Waiting for reports...", 
                                  bg="#2d2d30", fg="#cccccc", 
                                  font=("Consolas", 10), anchor="w", padx=10)
        self.status_bar.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))
        
        # 创建文本区域
        self.text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, 
                                                   bg="#1e1e1e", fg="white", 
                                                   font=("Consolas", 10),
                                                   insertbackground="white")
        self.text_area.pack(fill=tk.BOTH, expand=True)
        self.text_area.config(state='disabled')

        # 定义标签样式
        self.text_area.tag_config('header', foreground='#4ec9b0', font=('Consolas', 14, 'bold'))
        self.text_area.tag_config('executable', foreground='#ffd700', font=('Consolas', 12, 'bold'), underline=True)
        self.text_area.tag_config('timestamp', foreground='#808080', font=('Consolas', 9, 'italic'))
        self.text_area.tag_config('analyzer', foreground='#9cdcfe', font=('Consolas', 10, 'bold'))
        self.text_area.tag_config('high_risk', foreground='#f44747', font=('Consolas', 10, 'bold'))
        self.text_area.tag_config('medium_risk', foreground='#ff8c00', font=('Consolas', 10))
        self.text_area.tag_config('low_risk', foreground='#98fb98', font=('Consolas', 10))
        self.text_area.tag_config('description', foreground='#dcdcaa')
        self.text_area.tag_config('cvss', foreground='#ce9178')
        self.text_area.tag_config('evidence', foreground='#b5cea8')
        self.text_area.tag_config('action', foreground='#ff69b4', font=('Consolas', 10, 'bold'))
        self.text_area.tag_config('default', foreground='white')
        self.text_area.tag_config('separator', foreground='#555555')
        self.text_area.tag_config('section_separator', foreground='#4ec9b0', font=('Consolas', 10, 'bold'))

        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # 统计信息
        self.report_count = 0
        self.current_executable = None
        
        # 启动监听线程
        self.listener_thread = threading.Thread(target=self._listen_for_input, daemon=True)
        self.listener_thread.start()

    def _update_status(self, message):
        """更新状态栏"""
        self.status_bar.config(text=message)

    def _add_timestamp(self):
        """添加时间戳"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.text_area.insert(tk.END, f"[{timestamp}] ", 'timestamp')

    def _add_text_with_tags(self, text):
        """解析并添加带标签的文本"""
        self.text_area.config(state='normal')
        
        # 添加时间戳
        self._add_timestamp()
        
        lines = text.split('\n')
        in_evidence = False
        
        for line in lines:
            if not line.strip():
                self.text_area.insert(tk.END, '\n')
                continue
                
            # 匹配包含可执行文件名的报告标题
            if line.startswith("Vulnerability Report"):
                # 提取可执行文件名
                match = re.search(r'Vulnerability Report - (.+)$', line)
                if match:
                    executable_name = match.group(1)
                    self.current_executable = executable_name
                    self._update_status(f"Analyzing: {executable_name} | Reports: {self.report_count}")
                    
                    # 分开显示标题和可执行文件名
                    self.text_area.insert(tk.END, "Vulnerability Report - ", 'header')
                    self.text_area.insert(tk.END, executable_name + '\n', 'executable')
                else:
                    self.text_area.insert(tk.END, line + '\n', 'header')
                    
            elif line.startswith("-" * 50):
                self.text_area.insert(tk.END, line + '\n', 'separator')
                
            elif line.startswith("=" * 50):
                self.text_area.insert(tk.END, line + '\n', 'section_separator')
                self.report_count += 1
                
            elif line.startswith("Analyzer:"):
                self.text_area.insert(tk.END, line + '\n', 'analyzer')
                
            elif line.startswith("Level:"):
                level_match = re.search(r'Level:\s*(-?\d+)', line)
                if level_match:
                    level = int(level_match.group(1))
                    if level >= 8:
                        tag = 'high_risk'
                    elif 4 <= level < 8:
                        tag = 'medium_risk'
                    else:
                        tag = 'low_risk'
                    self.text_area.insert(tk.END, line + '\n', tag)
                else:
                    self.text_area.insert(tk.END, line + '\n', 'default')
                    
            elif line.startswith("CVSS Vector:"):
                self.text_area.insert(tk.END, line + '\n', 'cvss')
                
            elif line.startswith("Description:"):
                self.text_area.insert(tk.END, line + '\n', 'description')
                
            elif line.startswith("Evidence:"):
                self.text_area.insert(tk.END, line + '\n', 'evidence')
                in_evidence = True
                
            elif any(line.startswith(prefix) for prefix in 
                    ["[CGROUP]", "[ALERT]", "[WARNING]", "[ERROR]", 
                     "Sent SIGTERM", "Terminated", "Auto-isolation"]):
                self.text_area.insert(tk.END, line + '\n', 'action')
                
            elif in_evidence and line.startswith("  "):
                # 证据部分的缩进内容
                self.text_area.insert(tk.END, line + '\n', 'evidence')
                
            else:
                in_evidence = False
                self.text_area.insert(tk.END, line + '\n', 'default')

        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def _listen_for_input(self):
        """监听标准输入的报告"""
        report_buffer = []
        delimiter = "=" * 50

        try:
            for line in sys.stdin:
                report_buffer.append(line)

                # 检查是否收到完整报告
                if line.strip() == delimiter:
                    complete_report = "".join(report_buffer)
                    
                    # 在主线程中处理报告
                    self.root.after(0, self._process_report_block, complete_report)
                    
                    report_buffer = []
            
            # 处理最后可能残留的报告
            if report_buffer:
                self.root.after(0, self._process_report_block, "".join(report_buffer))
                
        except Exception as e:
            self.root.after(0, self._update_status, f"Error reading input: {e}")

    def _process_report_block(self, report_block):
        """处理完整的报告块"""
        # 写入日志文件
        with open(self.log_file_path, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            executable_info = f" - {self.current_executable}" if self.current_executable else ""
            f.write(f"\n--- Report Received at {timestamp}{executable_info} ---\n")
            f.write(report_block)
            f.write("\n")

        # 在 GUI 中显示
        self._add_text_with_tags(report_block)
        
        # 添加报告之间的分隔
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, "\n")
        self.text_area.config(state='disabled')

    def _on_closing(self):
        """窗口关闭时的处理"""
        # 保存最终统计信息
        with open(self.log_file_path, "a", encoding="utf-8") as f:
            f.write(f"\n--- Session ended at {datetime.datetime.now()} ---\n")
            f.write(f"Total reports processed: {self.report_count}\n")
        
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    app_root = tk.Tk()
    
    # 设置窗口图标（如果有的话）
    try:
        app_root.iconbitmap('icon.ico')
    except:
        pass
    
    gui = ReportWindow(app_root)
    app_root.mainloop()