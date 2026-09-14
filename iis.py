import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import pandas as pd

class IISForensicConsole:

    def __init__(self, root):
        self.root = root
        self.root.title("IIS Forensic Console - Professional Edition")
        self.root.geometry("1750x950")

        self.df = None
        self.filtered_df = None
        self.all_columns = []
        self.visible_columns = []

        self.setup_style()
        self.create_widgets()

    # ================= STYLE =================

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Treeview",
                        background="white",
                        foreground="black",
                        rowheight=26,
                        fieldbackground="white")

        style.configure("Treeview.Heading",
                        background="#f0f0f0",
                        foreground="black",
                        font=('Segoe UI', 10, 'bold'))

        style.map("Treeview",
                  background=[("selected", "#cce5ff")])

    # ================= UI =================

    def create_widgets(self):

        top = tk.Frame(self.root)
        top.pack(fill=tk.X, pady=5)

        tk.Button(top, text="Load Log", command=self.load_log).pack(side=tk.LEFT, padx=5)

        self.search = tk.Entry(top, width=40)
        self.search.pack(side=tk.LEFT, padx=5)

        tk.Button(top, text="Search", command=self.global_search).pack(side=tk.LEFT)
        tk.Button(top, text="Reset", command=self.reset_filter).pack(side=tk.LEFT, padx=5)

        tk.Button(top, text="Columns", command=self.manage_columns).pack(side=tk.RIGHT, padx=5)

        self.stats_label = tk.Label(self.root, font=("Segoe UI", 10))
        self.stats_label.pack(anchor="w", padx=10)

        frame = tk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frame, show="headings", selectmode="extended")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)

        self.tree.configure(yscrollcommand=vsb.set,
                            xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # Tags
        self.tree.tag_configure("error", background="#ffe5e5")
        self.tree.tag_configure("slow", background="#fff8cc")
        self.tree.tag_configure("heavy", background="#e6f2ff")

        # Copy bindings
        self.tree.bind("<Control-c>", self.copy_selected)
        self.tree.bind("<Button-3>", self.show_context_menu)

    # ================= LOAD =================

    def load_log(self):
        path = filedialog.askopenfilename(filetypes=[("Log files", "*.log")])
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            fields_line = [l for l in lines if l.startswith("#Fields:")][0]
            fields = fields_line.strip().split(" ")[1:]
            data = [l.strip().split(" ") for l in lines if not l.startswith("#")]

            self.df = pd.DataFrame(data, columns=fields)
            self.filtered_df = self.df.copy()

            self.all_columns = list(self.df.columns)
            self.visible_columns = list(self.df.columns)

            self.display_data(self.filtered_df.head(5000))
            self.update_stats()

        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ================= DISPLAY =================

    def display_data(self, df):

        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = self.visible_columns

        for col in self.visible_columns:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self.sort_column(c, False))
            self.tree.column(col,
                             width=150,
                             minwidth=60,
                             stretch=False,
                             anchor="w")

        ip_counts = df["c-ip"].value_counts() if "c-ip" in df.columns else {}

        for _, row in df.iterrows():
            tags = []

            try:
                if "sc-status" in df.columns and int(row["sc-status"]) >= 400:
                    tags.append("error")
            except:
                pass

            try:
                if "time-taken" in df.columns and int(row["time-taken"]) > 3000:
                    tags.append("slow")
            except:
                pass

            if "c-ip" in df.columns:
                if ip_counts.get(row["c-ip"], 0) > 200:
                    tags.append("heavy")

            values = [row[col] for col in self.visible_columns]
            self.tree.insert("", "end", values=values, tags=tags)

    # ================= COLUMN MANAGER =================

    def manage_columns(self):
        win = tk.Toplevel(self.root)
        win.title("Column Manager")
        win.geometry("350x500")

        vars_dict = {}

        for col in self.all_columns:
            var = tk.BooleanVar(value=(col in self.visible_columns))
            chk = tk.Checkbutton(win, text=col, variable=var)
            chk.pack(anchor="w")
            vars_dict[col] = var

        def apply():
            self.visible_columns = [col for col in self.all_columns if vars_dict[col].get()]
            if not self.visible_columns:
                messagebox.showwarning("Warning", "At least one column required.")
                return
            self.display_data(self.filtered_df.head(5000))
            win.destroy()

        tk.Button(win, text="Apply", command=apply).pack(pady=10)

    # ================= SORT =================

    def sort_column(self, col, reverse):
        try:
            self.filtered_df[col] = pd.to_numeric(self.filtered_df[col])
        except:
            pass

        self.filtered_df = self.filtered_df.sort_values(by=col, ascending=not reverse)
        self.display_data(self.filtered_df.head(5000))

    # ================= SEARCH =================

    def global_search(self):
        keyword = self.search.get()
        if not keyword:
            return

        mask = self.df.apply(lambda row: row.astype(str).str.contains(keyword).any(), axis=1)
        self.filtered_df = self.df[mask]
        self.display_data(self.filtered_df.head(5000))
        self.update_stats()

    def reset_filter(self):
        if self.df is None:
            return
        self.filtered_df = self.df.copy()
        self.display_data(self.filtered_df.head(5000))
        self.update_stats()

    # ================= COPY =================

    def copy_selected(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return

        rows = []
        for item in selected:
            row = self.tree.item(item)["values"]
            rows.append("\t".join(str(v) for v in row))

        result = "\n".join(rows)
        self.root.clipboard_clear()
        self.root.clipboard_append(result)

    def show_context_menu(self, event):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy Row", command=self.copy_selected)
        menu.post(event.x_root, event.y_root)

    # ================= STATS =================

    def update_stats(self):
        total = len(self.filtered_df)
        unique_ips = self.filtered_df["c-ip"].nunique() if "c-ip" in self.filtered_df.columns else 0

        self.stats_label.config(
            text=f"Total Requests: {total} | Unique IPs: {unique_ips}"
        )


if __name__ == "__main__":
    root = tk.Tk()
    app = IISForensicConsole(root)
    root.mainloop()