# import tkinter as tk
# from tkinter import scrolledtext
# import sys
# import threading
# import re
# import datetime

# class ReportWindow:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Vulnerability Report")
#         self.root.geometry("700x500")

#         self.log_file_path = "vulnerability_report.log"
        
#         self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg="#1e1e1e", fg="white", font=("Consolas", 10))
#         self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
#         self.text_area.config(state='disabled') 

#         self.text_area.tag_config('header', foreground='#4ec9b0', font=('Consolas', 12, 'bold', 'underline'))
#         self.text_area.tag_config('analyzer', foreground='#9cdcfe', font=('Consolas', 10, 'bold'))
#         self.text_area.tag_config('high_risk', foreground='#f44747', font=('Consolas', 10, 'bold'))
#         self.text_area.tag_config('medium_risk', foreground='#ff8c00') 
#         self.text_area.tag_config('low_risk', foreground='#cccccc') 
#         self.text_area.tag_config('description', foreground='#dcdcaa') 
#         self.text_area.tag_config('default', foreground='white')
#         self.text_area.tag_config('separator', foreground='#555555')

#         self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

#         self.listener_thread = threading.Thread(target=self._listen_for_input, daemon=True)
#         self.listener_thread.start()

#     def _add_text_with_tags(self, text):
#         self.text_area.config(state='normal') 
        
#         lines = text.split('\n')
#         for line in lines:
#             if not line.strip(): 
#                 continue
#             if line.startswith("Vulnerability Report"):
#                 self.text_area.insert(tk.END, line + '\n', 'header')
#             elif line.startswith("Analyzer:"):
#                 self.text_area.insert(tk.END, line + '\n', 'analyzer')
#             elif line.startswith("Description:"):
#                  self.text_area.insert(tk.END, line + '\n', 'description')
#             elif line.startswith("Level:"):
#                 level_match = re.search(r'Level:\s*(\d+)', line)
#                 if level_match:
#                     level = int(level_match.group(1))
#                     if level >= 8:
#                         self.text_area.insert(tk.END, line + '\n', 'high_risk')
#                     elif 4 <= level < 8:
#                         self.text_area.insert(tk.END, line + '\n', 'medium_risk')
#                     else:
#                         self.text_area.insert(tk.END, line + '\n', 'low_risk')
#                 else:
#                     self.text_area.insert(tk.END, line + '\n', 'default')
#             elif line.startswith("="*50) or line.startswith("-" * 50):
#                  self.text_area.insert(tk.END, line + '\n', 'separator')
#             else:
#                 self.text_area.insert(tk.END, line + '\n', 'default')

#         self.text_area.config(state='disabled')
#         self.text_area.see(tk.END) 

#     def _listen_for_input(self):
#         for block in sys.stdin:
#             if block:
#                 self.root.after(0, self._process_report, block)

#     def _process_report(self, report_text):
#         with open(self.log_file_path, "a", encoding="utf-8") as f:
#             timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#             f.write(f"--- Report Received at {timestamp} ---\n")
#             f.write(report_text)
#             f.write("\n\n")

#         self._add_text_with_tags(report_text)

#     def _on_closing(self):
#         self.root.destroy()
#         sys.exit(0) 

# if __name__ == "__main__":
#     app_root = tk.Tk()
#     gui = ReportWindow(app_root)
#     app_root.mainloop()
# report_gui.py (版本 2 - 优化日志记录)
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
        self.root.geometry("700x500")

        self.log_file_path = "vulnerability_report.log"
        
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg="#1e1e1e", fg="white", font=("Consolas", 10))
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.text_area.config(state='disabled')

        self.text_area.tag_config('header', foreground='#4ec9b0', font=('Consolas', 12, 'bold', 'underline'))
        self.text_area.tag_config('analyzer', foreground='#9cdcfe', font=('Consolas', 10, 'bold'))
        self.text_area.tag_config('high_risk', foreground='#f44747', font=('Consolas', 10, 'bold'))
        self.text_area.tag_config('medium_risk', foreground='#ff8c00')
        self.text_area.tag_config('low_risk', foreground='#cccccc')
        self.text_area.tag_config('description', foreground='#dcdcaa')
        self.text_area.tag_config('default', foreground='white')
        self.text_area.tag_config('separator', foreground='#555555')

        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # 启动后台线程来监听输入
        self.listener_thread = threading.Thread(target=self._listen_for_input, daemon=True)
        self.listener_thread.start()

    def _add_text_with_tags(self, text):
        """根据内容为文本添加颜色标签并插入到文本框"""
        self.text_area.config(state='normal')
        
        lines = text.split('\n')
        for line in lines:
            if not line.strip():
                continue
            # (这个函数的着色逻辑保持不变)
            if line.startswith("Vulnerability Report"):
                self.text_area.insert(tk.END, line + '\n', 'header')
            elif line.startswith("Analyzer:"):
                self.text_area.insert(tk.END, line + '\n', 'analyzer')
            elif line.startswith("Description:"):
                 self.text_area.insert(tk.END, line + '\n', 'description')
            elif line.startswith("Level:"):
                level_match = re.search(r'Level:\s*(\d+)', line)
                if level_match:
                    level = int(level_match.group(1))
                    if level >= 8:
                        self.text_area.insert(tk.END, line + '\n', 'high_risk')
                    elif 4 <= level < 8:
                        self.text_area.insert(tk.END, line + '\n', 'medium_risk')
                    else:
                        self.text_area.insert(tk.END, line + '\n', 'low_risk')
                else:
                    self.text_area.insert(tk.END, line + '\n', 'default')
            elif line.startswith("="*50) or line.startswith("-" * 50):
                 self.text_area.insert(tk.END, line + '\n', 'separator')
            else:
                self.text_area.insert(tk.END, line + '\n', 'default')

        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)

    def _listen_for_input(self):
        """
        ★★★★★ 这里是核心修改点 ★★★★★
        持续从 stdin 读取报告, 并按块（以分隔符为界）进行组合。
        """
        report_buffer = []  # 用于暂存单份报告的所有行
        delimiter = "=" * 50

        for line in sys.stdin:
            # 将当前行加入缓冲区
            report_buffer.append(line)

            # 检查当前行是否是报告的结束分隔符
            if line.strip() == delimiter:
                # 如果是，说明一份完整的报告已经接收完毕
                complete_report = "".join(report_buffer)
                
                # 将完整的报告块交由主线程处理
                self.root.after(0, self._process_report_block, complete_report)
                
                # 清空缓冲区，为下一份报告做准备
                report_buffer = []
        
        # 兜底：如果进程退出时缓冲区还有内容，也进行处理
        if report_buffer:
            self.root.after(0, self._process_report_block, "".join(report_buffer))


    def _process_report_block(self, report_block):
        """
        在主线程中处理一个完整的报告块：更新GUI和日志。
        这个函数现在接收的是完整的报告，而不是单行。
        """
        # 1. 以块为单位，写入日志文件
        with open(self.log_file_path, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # 写入单一的时间戳头
            f.write(f"--- Report Received at {timestamp} ---\n")
            # 写入完整的报告内容
            f.write(report_block)
            f.write("\n") # 在报告块后增加一个空行，方便分隔

        # 2. 在GUI窗口中显示（此部分逻辑不变）
        self._add_text_with_tags(report_block)

    def _on_closing(self):
        """处理窗口关闭事件"""
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    app_root = tk.Tk()
    # 将原来的 _process_report 重命名为 _process_report_block，逻辑更清晰
    gui = ReportWindow(app_root)
    app_root.mainloop()