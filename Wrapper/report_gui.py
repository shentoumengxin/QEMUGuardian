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

        self.listener_thread = threading.Thread(target=self._listen_for_input, daemon=True)
        self.listener_thread.start()

    def _add_text_with_tags(self, text):
        self.text_area.config(state='normal')
        
        lines = text.split('\n')
        for line in lines:
            if not line.strip():
                continue
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
        report_buffer = [] 
        delimiter = "=" * 50

        for line in sys.stdin:
            report_buffer.append(line)

            if line.strip() == delimiter:
                complete_report = "".join(report_buffer)
                
                self.root.after(0, self._process_report_block, complete_report)
                
                report_buffer = []
        
        if report_buffer:
            self.root.after(0, self._process_report_block, "".join(report_buffer))


    def _process_report_block(self, report_block):
        with open(self.log_file_path, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"--- Report Received at {timestamp} ---\n")
            f.write(report_block)
            f.write("\n") 

        self._add_text_with_tags(report_block)

    def _on_closing(self):
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    app_root = tk.Tk()
    gui = ReportWindow(app_root)
    app_root.mainloop()