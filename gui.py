#!/usr/bin/env python3
"""graphical interface for orcasec platform"""

import json
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

from pipeline import discover_modules, load_module, Pipeline, build_pipeline
from config import load_config, save_config


class OrcaGui:
    """main gui application"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("orcasec")
        self.root.geometry("900x650")
        self.root.configure(bg="#1a1a2e")
        self.config = load_config()
        self.modules = discover_modules()
        self.pipeline_stages = []
        self._build_styles()
        self._build_ui()

    def _build_styles(self):
        """configure ttk styles"""
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#1a1a2e")
        style.configure("TNotebook.Tab", background="#16213e", foreground="#e0e0e0",
                         padding=[10, 4])
        style.map("TNotebook.Tab", background=[("selected", "#0f3460")])
        style.configure("TFrame", background="#1a1a2e")
        style.configure("TLabel", background="#1a1a2e", foreground="#e0e0e0")
        style.configure("TButton", background="#0f3460", foreground="#e0e0e0")
        style.configure("Treeview", background="#16213e", foreground="#e0e0e0",
                         fieldbackground="#16213e")
        style.configure("Treeview.Heading", background="#0f3460", foreground="#00d4ff")

    def _build_ui(self):
        """build the main interface"""
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self._build_modules_tab(notebook)
        self._build_pipeline_tab(notebook)
        self._build_output_frame()

    def _build_modules_tab(self, notebook):
        """build the module browser tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="modules")
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.module_tree = ttk.Treeview(tree_frame, columns=("description",),
                                         show="headings", height=15)
        self.module_tree.heading("#0", text="module")
        self.module_tree.heading("description", text="description")
        self.module_tree.column("description", width=500)
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                                   command=self.module_tree.yview)
        self.module_tree.configure(yscrollcommand=scrollbar.set)
        self.module_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        for name, info in sorted(self.modules.items()):
            self.module_tree.insert("", tk.END, values=(name, info["description"]))
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="run selected", command=self._run_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="add to pipeline", command=self._add_to_pipeline).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="refresh", command=self._refresh_modules).pack(side=tk.LEFT, padx=2)

    def _build_pipeline_tab(self, notebook):
        """build the pipeline builder tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="pipeline")
        self.pipeline_list = tk.Listbox(frame, bg="#16213e", fg="#e0e0e0",
                                         selectbackground="#0f3460", height=10)
        self.pipeline_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="run pipeline", command=self._run_pipeline).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="run parallel", command=self._run_pipeline_parallel).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="remove selected", command=self._remove_stage).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="clear", command=self._clear_pipeline).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="save", command=self._save_pipeline).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="load", command=self._load_pipeline).pack(side=tk.LEFT, padx=2)

    def _build_output_frame(self):
        """build the output text area"""
        output_frame = ttk.Frame(self.root)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Label(output_frame, text="output").pack(anchor=tk.W)
        self.output = scrolledtext.ScrolledText(output_frame, height=12,
                                                 bg="#0a0a1a", fg="#00ff88",
                                                 font=("Courier", 10),
                                                 insertbackground="#00ff88")
        self.output.pack(fill=tk.BOTH, expand=True)
        btn_frame = ttk.Frame(output_frame)
        btn_frame.pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame, text="clear output", command=self._clear_output).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="save output", command=self._save_output).pack(side=tk.LEFT, padx=2)

    def _write_output(self, text):
        """append text to output area (thread-safe)"""
        self.root.after(0, lambda: self._append_output(text))

    def _append_output(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def _run_selected(self):
        """run the selected module in a background thread"""
        selection = self.module_tree.selection()
        if not selection:
            return
        values = self.module_tree.item(selection[0])["values"]
        module_name = values[0]
        self._write_output(f"--- running {module_name} ---")
        thread = threading.Thread(target=self._execute_module, args=(module_name,), daemon=True)
        thread.start()

    def _execute_module(self, name):
        """run a module and capture output"""
        import io
        from contextlib import redirect_stdout, redirect_stderr
        buf = io.StringIO()
        try:
            mod = load_module(name)
            if hasattr(mod, "main"):
                with redirect_stdout(buf), redirect_stderr(buf):
                    mod.main()
                self._write_output(buf.getvalue())
            else:
                self._write_output(f"module '{name}' has no main() function")
        except Exception as e:
            self._write_output(f"error: {e}")
        self._write_output(f"--- {name} complete ---")

    def _add_to_pipeline(self):
        """add selected module to pipeline"""
        selection = self.module_tree.selection()
        if not selection:
            return
        values = self.module_tree.item(selection[0])["values"]
        module_name = values[0]
        self.pipeline_stages.append({"name": module_name, "module": module_name})
        self.pipeline_list.insert(tk.END, module_name)

    def _remove_stage(self):
        """remove selected stage from pipeline"""
        selection = self.pipeline_list.curselection()
        if selection:
            idx = selection[0]
            self.pipeline_list.delete(idx)
            self.pipeline_stages.pop(idx)

    def _clear_pipeline(self):
        """clear all pipeline stages"""
        self.pipeline_list.delete(0, tk.END)
        self.pipeline_stages.clear()

    def _run_pipeline(self):
        """run pipeline sequentially"""
        if not self.pipeline_stages:
            return
        self._write_output("--- running pipeline (sequential) ---")
        thread = threading.Thread(target=self._execute_pipeline, args=(False,), daemon=True)
        thread.start()

    def _run_pipeline_parallel(self):
        """run pipeline in parallel"""
        if not self.pipeline_stages:
            return
        self._write_output("--- running pipeline (parallel) ---")
        thread = threading.Thread(target=self._execute_pipeline, args=(True,), daemon=True)
        thread.start()

    def _execute_pipeline(self, parallel):
        """run the configured pipeline"""
        try:
            pipe = build_pipeline(self.pipeline_stages)
            if parallel:
                pipe.run_parallel()
            else:
                pipe.run()
            self._write_output(pipe.summary())
        except Exception as e:
            self._write_output(f"pipeline error: {e}")
        self._write_output("--- pipeline complete ---")

    def _save_pipeline(self):
        """save pipeline to json file"""
        if not self.pipeline_stages:
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("json", "*.json")])
        if path:
            with open(path, "w") as f:
                json.dump({"name": "custom", "stages": self.pipeline_stages}, f, indent=2)
            self._write_output(f"pipeline saved to {path}")

    def _load_pipeline(self):
        """load pipeline from json file"""
        path = filedialog.askopenfilename(filetypes=[("json", "*.json")])
        if path:
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                self.pipeline_stages = data.get("stages", [])
                self.pipeline_list.delete(0, tk.END)
                for stage in self.pipeline_stages:
                    self.pipeline_list.insert(tk.END, stage.get("name", stage.get("module")))
                self._write_output(f"loaded pipeline from {path}")
            except (IOError, json.JSONDecodeError) as e:
                self._write_output(f"error loading pipeline: {e}")

    def _refresh_modules(self):
        """refresh module list"""
        self.modules = discover_modules()
        self.module_tree.delete(*self.module_tree.get_children())
        for name, info in sorted(self.modules.items()):
            self.module_tree.insert("", tk.END, values=(name, info["description"]))

    def _clear_output(self):
        self.output.delete("1.0", tk.END)

    def _save_output(self):
        """save output to file"""
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("text", "*.txt"), ("all", "*.*")])
        if path:
            with open(path, "w") as f:
                f.write(self.output.get("1.0", tk.END))

    def run(self):
        self.root.mainloop()


def main():
    """launch the gui"""
    app = OrcaGui()
    app.run()


if __name__ == "__main__":
    main()
