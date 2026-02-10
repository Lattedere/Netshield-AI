"""
GUI Launcher for Network Capture and Prediction Tool
Double-click this file to start the capture tool with a simple GUI interface.
"""
import os
import sys
import subprocess
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from pathlib import Path

class CaptureLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Capture & Prediction Tool")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        self.process = None
        self.is_running = False
        
        # Create UI
        self.create_widgets()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_widgets(self):
        # Title
        title_frame = tk.Frame(self.root)
        title_frame.pack(pady=10)
        tk.Label(title_frame, text="Network Capture & Prediction Tool", 
                font=("Arial", 16, "bold")).pack()
        
        # Status frame
        status_frame = tk.Frame(self.root)
        status_frame.pack(pady=5)
        self.status_label = tk.Label(status_frame, text="Status: Stopped", 
                                     font=("Arial", 10), fg="red")
        self.status_label.pack()
        
        # Button frame
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.start_btn = tk.Button(button_frame, text="Start Capture", 
                                   command=self.start_capture,
                                   bg="#4CAF50", fg="white", 
                                   font=("Arial", 12, "bold"),
                                   width=15, height=2)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(button_frame, text="Stop Capture", 
                                  command=self.stop_capture,
                                  bg="#f44336", fg="white",
                                  font=("Arial", 12, "bold"),
                                  width=15, height=2,
                                  state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Output frame
        output_frame = tk.Frame(self.root)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(output_frame, text="Output:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, 
                                                     wrap=tk.WORD,
                                                     font=("Consolas", 9),
                                                     bg="#1e1e1e",
                                                     fg="#d4d4d4",
                                                     insertbackground="white")
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Info label
        info_label = tk.Label(self.root, 
                             text="Note: Packet capture requires administrator privileges.\n"
                                  "If capture fails, try running as administrator.",
                             font=("Arial", 8), fg="gray", justify=tk.LEFT)
        info_label.pack(pady=5)
        
    def start_capture(self):
        if self.is_running:
            return
            
        script_path = Path(__file__).parent / "capture_predict_live.py"
        if not script_path.exists():
            messagebox.showerror("Error", 
                               f"Could not find capture_predict_live.py\n"
                               f"Expected at: {script_path}")
            return
        
        try:
            self.is_running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text="Status: Running...", fg="green")
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, "Starting capture...\n")
            self.output_text.insert(tk.END, "=" * 60 + "\n\n")
            
            # Start the capture script in a subprocess
            self.process = subprocess.Popen(
                [sys.executable, str(script_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Start thread to read output
            self.output_thread = threading.Thread(target=self.read_output, daemon=True)
            self.output_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture:\n{str(e)}")
            self.is_running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Status: Error", fg="red")
    
    def read_output(self):
        """Read output from the subprocess and display it in the text widget"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if not line:
                    break
                self.root.after(0, self.append_output, line)
        except Exception as e:
            self.root.after(0, self.append_output, f"\n[ERROR] {str(e)}\n")
        finally:
            if self.process:
                self.process.wait()
            self.root.after(0, self.on_process_end)
    
    def append_output(self, text):
        """Append text to the output widget (thread-safe)"""
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
    
    def on_process_end(self):
        """Called when the process ends"""
        self.is_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped", fg="red")
        self.append_output("\n" + "=" * 60 + "\n")
        self.append_output("Capture stopped.\n")
    
    def stop_capture(self):
        if self.process and self.is_running:
            try:
                self.process.terminate()
                # Give it a moment to terminate gracefully
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't terminate
                self.process.kill()
            except Exception as e:
                self.append_output(f"\n[ERROR] Error stopping capture: {str(e)}\n")
            
            self.is_running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Status: Stopped", fg="red")
            self.append_output("\nCapture stopped by user.\n")
    
    def on_closing(self):
        """Handle window close event"""
        if self.is_running:
            if messagebox.askokcancel("Quit", "Capture is running. Stop and quit?"):
                self.stop_capture()
                self.root.after(500, self.root.destroy)
        else:
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CaptureLauncher(root)
    root.mainloop()

