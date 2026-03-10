#!/usr/bin/env python3
"""
CIAhO – Cookie Impact Analyzer GUI
Run: python ciaho_gui.py
"""

import sys
import os
import threading
import queue
import json
import re
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
from urllib.parse import urlparse

import tkinter.filedialog as filedialog

_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _DIR)

# ── Catppuccin Mocha palette ─────────────────
C_BASE    = "#1e1e2e"
C_MANTLE  = "#181825"
C_SURFACE = "#313244"
C_OVERLAY = "#45475a"
C_TEXT    = "#cdd6f4"
C_GREEN   = "#a6e3a1"
C_YELLOW  = "#f9e2af"
C_BLUE    = "#89b4fa"
C_RED     = "#f38ba8"
C_CYAN    = "#89dceb"
C_MAUVE   = "#cba6f7"
C_PINK    = "#f5c2e7"


# ── stdout redirector ────────────────────────
class _Redir:
    def __init__(self, q: queue.Queue, tag: str = "normal"):
        self.q, self.tag = q, tag

    def write(self, text: str):
        self.q.put((self.tag, text))

    def flush(self):
        pass


# ── Main GUI class ───────────────────────────
class CiahoGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CIAhO")
        self.geometry("1200x820")
        self.minsize(960, 640)
        self.configure(bg=C_BASE)

        self._q = queue.Queue()
        self._outdir = None
        self._busy   = False
        self._batch_results: list[dict] = []  # ranking history

        self._build()
        self._poll()

    # ════════════════════════════════════════
    #  UI construction
    # ════════════════════════════════════════

    def _build(self):
        # accent bar
        tk.Frame(self, bg=C_MAUVE, height=3).pack(fill="x")

        # ── header ──
        hf = tk.Frame(self, bg=C_BASE, pady=10)
        hf.pack(fill="x", padx=20)
        tk.Label(hf, text="🍪  CIAhO",
                 font=("Segoe UI", 17, "bold"),
                 bg=C_BASE, fg=C_TEXT).pack(side="left")
        tk.Label(hf,
                 text="  compares network traffic after accepting and rejecting cookies",
                 font=("Segoe UI", 9), bg=C_BASE, fg=C_OVERLAY).pack(side="left")

        # ── URL bar ──
        uf = tk.Frame(self, bg=C_SURFACE, pady=8, padx=10)
        uf.pack(fill="x", padx=20, pady=(0, 10))

        tk.Label(uf, text=" URL(s): ", bg=C_SURFACE, fg=C_TEXT,
                 font=("Segoe UI", 11)).pack(side="left")

        self._url = tk.StringVar()
        self._entry = tk.Entry(
            uf, textvariable=self._url,
            font=("Consolas", 12),
            bg=C_MANTLE, fg=C_TEXT, insertbackground=C_TEXT,
            relief="flat", bd=0, width=52,
        )
        self._entry.pack(side="left", padx=6, ipady=6)
        self._entry.bind("<Return>", lambda _: self._go())
        self._entry.focus_set()

        self._loadbtn = tk.Button(
            uf, text="📂", command=self._load_list,
            font=("Segoe UI", 11),
            bg=C_SURFACE, fg=C_CYAN,
            relief="flat", padx=6, pady=5,
            cursor="hand2",
            activebackground=C_MANTLE,
        )
        self._loadbtn.pack(side="left", padx=(0, 4))

        self._btn = tk.Button(
            uf, text="▶  Analyze", command=self._go,
            font=("Segoe UI", 11, "bold"),
            bg=C_MAUVE, fg=C_BASE,
            relief="flat", padx=18, pady=5,
            cursor="hand2",
            activebackground="#b48ef7", activeforeground=C_BASE,
        )
        self._btn.pack(side="left", padx=10)

        self._status = tk.Label(uf, text="", bg=C_SURFACE,
                                fg=C_YELLOW, font=("Segoe UI", 10))
        self._status.pack(side="left")

        # ── paned: terminal (top) + results (bottom) ──
        self._paned = tk.PanedWindow(
            self, orient="vertical",
            bg=C_BASE, sashwidth=7, sashrelief="flat", bd=0,
        )
        self._paned.pack(fill="both", expand=True, padx=20, pady=(0, 6))

        # terminal panel
        term_outer = tk.Frame(self._paned, bg=C_BASE)
        tk.Label(term_outer, text="  Analysis log",
                 bg=C_MANTLE, fg=C_MAUVE,
                 font=("Consolas", 9), anchor="w").pack(fill="x")
        self._term = scrolledtext.ScrolledText(
            term_outer,
            font=("Consolas", 10),
            bg=C_MANTLE, fg=C_TEXT,
            relief="flat", state="disabled", wrap="word",
            insertbackground=C_TEXT,
        )
        self._term.pack(fill="both", expand=True)
        for tag, col in [
            ("green",  C_GREEN), ("yellow", C_YELLOW),
            ("blue",   C_BLUE),  ("red",    C_RED),
            ("cyan",   C_CYAN),  ("normal", C_TEXT),
            ("dim",    C_OVERLAY),
        ]:
            self._term.tag_config(tag, foreground=col)
        self._paned.add(term_outer, minsize=180)

        # results panel
        self._rf = tk.Frame(self._paned, bg=C_BASE)
        self._ph = tk.Label(
            self._rf,
            text="➤  Results will appear here after the analysis completes",
            bg=C_BASE, fg=C_OVERLAY, font=("Segoe UI", 12),
        )
        self._ph.pack(expand=True)

        # notebook (built once, swapped in after analysis)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=C_BASE, borderwidth=0)
        style.configure("TNotebook.Tab", background=C_SURFACE,
                        foreground=C_TEXT, padding=[14, 5],
                        font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", C_MAUVE)],
                  foreground=[("selected", C_BASE)])
        style.configure("Vertical.TScrollbar", background=C_SURFACE,
                        troughcolor=C_MANTLE, borderwidth=0, arrowsize=12)
        style.configure("Horizontal.TScrollbar", background=C_SURFACE,
                        troughcolor=C_MANTLE, borderwidth=0, arrowsize=12)

        self._nb = ttk.Notebook(self._rf)
        self._paned.add(self._rf, minsize=200)

        # ── bottom bar ──
        bb = tk.Frame(self, bg=C_MANTLE, height=26)
        bb.pack(fill="x", side="bottom")
        self._bar = tk.Label(bb, text="Ready.", bg=C_MANTLE,
                             fg=C_OVERLAY, font=("Segoe UI", 9))
        self._bar.pack(side="left", padx=10)
        self._openbtn = tk.Button(
            bb, text="📁  Open results folder",
            command=self._open_folder,
            bg=C_MANTLE, fg=C_CYAN,
            relief="flat", font=("Segoe UI", 9),
            cursor="hand2", state="disabled",
            activebackground=C_MANTLE,
        )
        self._openbtn.pack(side="right", padx=10)
        self._pdfbtn = tk.Button(
            bb, text="📄  Open PDF report",
            command=self._open_pdf,
            bg=C_MANTLE, fg=C_MAUVE,
            relief="flat", font=("Segoe UI", 9),
            cursor="hand2", state="disabled",
            activebackground=C_MANTLE,
        )
        self._pdfbtn.pack(side="right", padx=2)

    def _load_list(self):
        """Open a .txt file and load URLs (one per line) into the entry field."""
        path = filedialog.askopenfilename(
            title="Select URL list (.txt)",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        urls = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
        if urls:
            self._url.set(", ".join(urls))
            self._bar.configure(text=f"Loaded {len(urls)} URL(s) from {os.path.basename(path)}")
        else:
            messagebox.showwarning("Empty file", "No valid URLs found in the selected file.")

    # ════════════════════════════════════════
    #  Log handling
    # ════════════════════════════════════════

    def _poll(self):
        try:
            while True:
                tag, text = self._q.get_nowait()
                self._log(text, tag)
        except queue.Empty:
            pass
        self.after(40, self._poll)

    def _tag_of(self, line: str) -> str:
        s = line.lstrip()
        if s.startswith("[+]") or "✓" in s or "saved" in s.lower():
            return "green"
        if s.startswith("[*]"):
            return "blue"
        if s.startswith("[ERROR]") or s.startswith("[WARN") or "error" in s.lower():
            return "red"
        if s[:1] in "═─╔╚║╠╝╗":
            return "yellow"
        return "normal"

    def _log(self, text: str, hint: str = "normal"):
        self._term.configure(state="normal")
        for line in text.splitlines(keepends=True):
            tag = self._tag_of(line) if hint == "normal" else hint
            self._term.insert("end", line, tag)
        self._term.see("end")
        self._term.configure(state="disabled")

    # ════════════════════════════════════════
    #  Analysis
    # ════════════════════════════════════════

    def _go(self):
        if self._busy:
            return
        raw = self._url.get().strip()
        if not raw:
            messagebox.showwarning("No URL", "Enter a website address, e.g. bbc.com")
            return

        # Support comma-separated URLs
        urls = [u.strip() for u in raw.split(",") if u.strip()]

        self._busy = True
        self._btn.configure(state="disabled", text="⏳  Analyzing…")
        label = urls[0] if len(urls) == 1 else f"{len(urls)} sites"
        self._status.configure(text="Analysis in progress…", fg=C_YELLOW)
        self._bar.configure(text=f"Analyzing: {label}")

        # reset terminal
        self._term.configure(state="normal")
        self._term.delete("1.0", "end")
        self._term.configure(state="disabled")

        # reset results
        for tab in self._nb.tabs():
            self._nb.forget(tab)
        self._nb.pack_forget()
        self._ph.pack(expand=True)

        threading.Thread(target=self._run_batch, args=(urls,), daemon=True).start()

    def _run_batch(self, urls: list):
        """Analyse one or more URLs sequentially and push results to the GUI."""
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout = _Redir(self._q, "normal")
        sys.stderr = _Redir(self._q, "red")
        batch: list[dict] = []
        last_outdir = last_result = None
        try:
            from ciaho import (CookieAnalyzer, _check_java, _ensure_bmp,
                               _detect_default_browser)
            _check_java()
            _ensure_bmp()
            btype, bbinary = _detect_default_browser()

            for idx, url in enumerate(urls, 1):
                if len(urls) > 1:
                    print(f"\n[*] ({idx}/{len(urls)}) Analysing: {url}")

                norm   = url if "://" in url else "https://" + url
                netloc = urlparse(norm).netloc or url
                safe   = re.sub(r"[^a-zA-Z0-9._-]", "_", netloc)
                ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
                outdir = os.path.abspath(os.path.join(_DIR, f"output_{safe}_{ts}"))
                print(f"  Results will be saved to: {outdir}/\n")

                entry = {"url": netloc or url, "score": None, "grade": None,
                         "gdpr_risk": None, "fp_risk": None,
                         "output_dir": outdir, "result": None}
                try:
                    analyzer = CookieAnalyzer(url, output_dir=outdir,
                                              browser_type=btype, browser_binary=bbinary)
                    result = analyzer.analyze()
                    ps = result.get("privacy_score", {})
                    entry["score"]     = ps.get("score")
                    entry["grade"]     = ps.get("grade")
                    entry["gdpr_risk"] = result.get("gdpr", {}).get("overall_risk", "NONE")
                    entry["fp_risk"]   = result.get("fingerprinting", {}).get("risk", "NONE")
                    entry["result"]    = result
                    last_outdir = outdir
                    last_result = result
                except Exception as exc:
                    import traceback
                    traceback.print_exc()
                    entry["error"] = str(exc)

                batch.append(entry)

        except Exception as exc:
            import traceback
            traceback.print_exc()
        finally:
            sys.stdout, sys.stderr = old_out, old_err

        self.after(0, self._done_batch, batch, last_outdir, last_result)

    # keep old _run for compatibility if anything else calls it
    def _run(self, url: str):
        self._run_batch([url])

    def _done_batch(self, batch: list, last_outdir, last_result):
        self._busy = False
        self._btn.configure(state="normal", text="▶  Analyze")

        errors = [e for e in batch if e.get("error")]
        ok     = [e for e in batch if not e.get("error")]

        if not ok:
            # all failed
            self._status.configure(text="❌  Error", fg=C_RED)
            self._bar.configure(text=f"Error: {errors[0].get('error','?')[:100]}")
            messagebox.showerror("Analysis error", errors[0].get("error", "Unknown error"))
            return

        if errors:
            self._status.configure(text=f"⚠️  Done ({len(errors)} error(s))", fg=C_YELLOW)
        else:
            self._status.configure(text="✓  Done!", fg=C_GREEN)

        self._outdir = last_outdir
        self._bar.configure(text=f"Results: {last_outdir}")
        self._openbtn.configure(state="normal")
        self._pdfbtn.configure(state="normal")

        # Accumulate into session ranking history
        self._batch_results.extend(batch)

        self._show(last_outdir, last_result, batch)

    def _done(self, outdir, result, error):
        """Legacy single-URL done handler – delegates to _done_batch."""
        if error:
            self._done_batch([{"url": outdir, "error": error,
                               "score": None, "grade": None,
                               "gdpr_risk": None, "fp_risk": None}],
                             None, None)
        else:
            entry = {
                "url":       urlparse("https://" + outdir).netloc or outdir,
                "score":     result.get("privacy_score", {}).get("score"),
                "grade":     result.get("privacy_score", {}).get("grade"),
                "gdpr_risk": result.get("gdpr", {}).get("overall_risk", "NONE"),
                "fp_risk":   result.get("fingerprinting", {}).get("risk", "NONE"),
                "output_dir": outdir,
                "result":    result,
            }
            self._done_batch([entry], outdir, result)

    # ════════════════════════════════════════
    #  Results panel
    # ════════════════════════════════════════

    def _show(self, outdir: str, result: dict, batch: list | None = None):
        self._ph.pack_forget()

        ct = tk.Frame(self._nb, bg=C_BASE)
        self._nb.add(ct, text="  📊  Charts  ")
        self._charts_tab(ct, outdir)

        ps_t = tk.Frame(self._nb, bg=C_BASE)
        self._nb.add(ps_t, text="  🔒  Privacy Score  ")
        self._privacy_score_tab(ps_t, result)

        st = tk.Frame(self._nb, bg=C_BASE)
        self._nb.add(st, text="  📋  Summary  ")
        self._summary_tab(st, result)

        cdt = tk.Frame(self._nb, bg=C_BASE)
        self._nb.add(cdt, text="  🍪  Cookie Details  ")
        self._cookie_details_tab(cdt, result)

        gt = tk.Frame(self._nb, bg=C_BASE)
        self._nb.add(gt, text="  🔴  GDPR  ")
        self._gdpr_tab(gt, result.get("gdpr", {}))

        fpt = tk.Frame(self._nb, bg=C_BASE)
        self._nb.add(fpt, text="  🖆  Fingerprinting  ")
        self._fingerprinting_tab(fpt, result.get("fingerprinting", {}))

        # Ranking tab – show cumulative session history
        if self._batch_results:
            rt = tk.Frame(self._nb, bg=C_BASE)
            self._nb.add(rt, text="  🏆  Ranking  ")
            self._ranking_tab(rt, self._batch_results)

        jt = tk.Frame(self._nb, bg=C_BASE)
        self._nb.add(jt, text="  { }  JSON  ")
        self._json_tab(jt, result)

        self._nb.pack(fill="both", expand=True)

    # ── scrollable helper ────────────────────
    def _scrollable(self, parent, horiz: bool = False):
        canvas = tk.Canvas(parent, bg=C_BASE, highlightthickness=0)
        vsb    = ttk.Scrollbar(parent, orient="vertical",   command=canvas.yview)
        inner  = tk.Frame(canvas, bg=C_BASE)

        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.configure(yscrollcommand=vsb.set)

        if horiz:
            hsb = ttk.Scrollbar(parent, orient="horizontal", command=canvas.xview)
            canvas.configure(xscrollcommand=hsb.set)
            hsb.pack(side="bottom", fill="x")

        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.create_window((0, 0), window=inner, anchor="nw")

        # mousewheel (Linux)
        canvas.bind("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind("<Button-5>", lambda e: canvas.yview_scroll( 1, "units"))
        inner.bind("<Button-4>",  lambda e: canvas.yview_scroll(-1, "units"))
        inner.bind("<Button-5>",  lambda e: canvas.yview_scroll( 1, "units"))
        return canvas, inner

    # ── Charts tab ───────────────────────────
    def _charts_tab(self, parent, outdir: str):
        _, inner = self._scrollable(parent, horiz=True)

        for fname, title in [
            ("domain_categories.png", "Domain categories (pie charts)"),
            ("comparison.png",        "Comparison – requests & cookies"),
        ]:
            path = os.path.join(outdir, fname)
            if not os.path.isfile(path):
                tk.Label(inner, text=f"Missing file: {fname}",
                         bg=C_BASE, fg=C_RED, font=("Segoe UI", 10)).pack(pady=6)
                continue
            try:
                img = tk.PhotoImage(file=path)
                lf  = tk.LabelFrame(inner, text=f"  {title}  ",
                                    bg=C_SURFACE, fg=C_MAUVE,
                                    font=("Segoe UI", 10, "bold"),
                                    relief="flat", bd=1)
                lf.pack(fill="x", padx=14, pady=10, anchor="nw")
                lbl = tk.Label(lf, image=img, bg=C_SURFACE)
                lbl.image = img       # keep GC reference
                lbl.pack(padx=4, pady=6, anchor="w")
            except Exception as e:
                tk.Label(inner, text=f"Error loading {fname}: {e}",
                         bg=C_BASE, fg=C_RED).pack()

    # ── Summary tab ──────────────────────────
    def _summary_tab(self, parent, r: dict):
        _, inner = self._scrollable(parent)

        def section(title: str) -> tk.Frame:
            f = tk.Frame(inner, bg=C_SURFACE, padx=18, pady=10)
            f.pack(fill="x", padx=16, pady=(10, 0))
            tk.Label(f, text=title, bg=C_SURFACE, fg=C_MAUVE,
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))
            return f

        def kv(frame: tk.Frame, key: str, val, color: str = C_TEXT):
            row = tk.Frame(frame, bg=C_SURFACE)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=key, bg=C_SURFACE, fg=C_OVERLAY,
                     width=36, anchor="w",
                     font=("Segoe UI", 10)).pack(side="left")
            tk.Label(row, text=str(val), bg=C_SURFACE, fg=color,
                     font=("Consolas", 10, "bold")).pack(side="left")

        # ── Consent ──
        consent = r.get("consent", {})
        sf = section("🔐  Consent banner detection")
        kv(sf, "ACCEPT button:",
           "YES ✓" if consent.get("accept_found") else "NO ✗",
           C_GREEN if consent.get("accept_found") else C_RED)
        kv(sf, "NECESSARY ONLY button:",
           "YES ✓" if consent.get("necessary_found") else "NO ✗",
           C_GREEN if consent.get("necessary_found") else C_YELLOW)
        kv(sf, "REJECT button:",
           "YES ✓" if consent.get("reject_found") else "NO ✗",
           C_GREEN if consent.get("reject_found") else C_RED)

        # ── Requests ──
        reqs = r.get("requests", {})
        nf   = section("🌐  Network requests (HAR)")
        acc  = reqs.get("accept_total", 0)
        nec  = reqs.get("necessary_total", 0)
        rej  = reqs.get("reject_total", 0)
        diff = reqs.get("difference",   acc - rej)
        pct  = f"{diff/rej*100:.1f}%" if rej else "–"
        kv(nf, "Requests after ACCEPT:",              acc,          C_RED)
        kv(nf, "Requests NECESSARY ONLY:",            nec,          C_YELLOW)
        kv(nf, "Requests after REJECT:",              rej,          C_GREEN)
        kv(nf, "Excess on accept:",
           f"+{diff}" if diff >= 0 else str(diff), C_YELLOW)
        kv(nf, "Percentage increase:",                pct,          C_YELLOW)

        # ── Domains ──
        doms = r.get("domains", {})
        df   = section("🔗  Domains")
        kv(df, "Unique domains (acc / nec. / rej):",
           f"{doms.get('accept_total', 0)} / {doms.get('necessary_total', 0)} / {doms.get('reject_total', 0)}")
        kv(df, "Tracking domains (acc / nec. / rej):",
           f"{doms.get('accept_tracking', 0)} / {doms.get('necessary_tracking', 0)} / {doms.get('reject_tracking', 0)}", C_RED)

        for dom_key, dom_title in [
            ("only_in_accept",    "🎯  Domains ONLY after accept"),
            ("only_in_necessary", "🎯  Domains ONLY on necessary"),
        ]:
            only_d = doms.get(dom_key, [])
            if only_d:
                odf = section(f"{dom_title} ({len(only_d)}x)")
                try:
                    from ciaho import DOMAIN_COMPANY as _DC
                    def _co(dom):
                        dom = dom.lower().lstrip(".")
                        if dom in _DC:
                            return _DC[dom]
                        parts = dom.split(".")
                        for i in range(1, len(parts) - 1):
                            p = ".".join(parts[i:])
                            if p in _DC:
                                return _DC[p]
                        return ""
                except Exception:
                    def _co(_): return ""
                for d in only_d[:30]:
                    company = _co(d)
                    label   = f"{d}  [{company}]" if company else d
                    kv(odf, "", label, C_RED)
                if len(only_d) > 30:
                    tk.Label(odf, text=f"  … and {len(only_d)-30} more (see JSON tab)",
                             bg=C_SURFACE, fg=C_OVERLAY,
                             font=("Segoe UI", 9)).pack(anchor="w")

        # ── Categories ──
        cat_labels = {
            "advertising":        ("📣", "Advertising"),
            "analytics":          ("📈", "Analytics"),
            "social_media":       ("💬", "Social media"),
            "cdn_infrastructure": ("🏗️", "CDN / Infrastructure"),
            "other":              ("🔹", "Other"),
        }
        for scenario_key, scenario_title in [
            ("accept_categories",    "📂  Domain categories after ACCEPT"),
            ("necessary_categories", "📂  Domain categories NECESSARY ONLY"),
            ("reject_categories",    "📂  Domain categories after REJECT"),
        ]:
            cats = doms.get(scenario_key, {})
            if not any(cats.values()):
                continue
            catf = section(scenario_title)
            for cat, cat_domains in sorted(cats.items()):
                if not cat_domains:
                    continue
                icon, label = cat_labels.get(cat, ("•", cat))
                kv(catf, f"{icon}  {label}:", f"{len(cat_domains)} domains", C_CYAN)

        # ── Cookies ──
        ck = r.get("cookies", {})
        cf = section("🍪  Cookies")
        kv(cf, "Browser cookies (acc / nec. / rej):",
           f"{ck.get('accept_browser_count',0)} / {ck.get('necessary_browser_count',0)} / {ck.get('reject_browser_count',0)}")
        kv(cf, "HAR cookies     (acc / nec. / rej):",
           f"{ck.get('accept_har_count',0)} / {ck.get('necessary_har_count',0)} / {ck.get('reject_har_count',0)}")

        for cookie_key, section_title in [
            ("only_in_accept",    "🎯  Cookies ONLY after accept"),
            ("only_in_necessary", "🎯  Cookies ONLY on necessary"),
        ]:
            names = ck.get(cookie_key, [])
            if names:
                ockf = section(f"{section_title} ({len(names)}x)")
                for c in names[:25]:
                    kv(ockf, "", c, C_RED)
                if len(names) > 25:
                    tk.Label(ockf, text=f"  … and {len(names)-25} more (see JSON tab)",
                             bg=C_SURFACE, fg=C_OVERLAY,
                             font=("Segoe UI", 9)).pack(anchor="w")

        # bottom padding
        tk.Frame(inner, bg=C_BASE, height=16).pack()

    # ── Privacy Score tab ────────────────────
    def _privacy_score_tab(self, parent, r: dict):
        _, inner = self._scrollable(parent)

        ps = r.get("privacy_score", {})
        if not ps:
            tk.Label(inner,
                     text="No Privacy Score data (old analysis file or analysis not yet run).",
                     bg=C_BASE, fg=C_OVERLAY, font=("Segoe UI", 10),
                     wraplength=700, justify="left").pack(padx=20, pady=20, anchor="w")
            return

        score   = ps.get("score", 0)
        grade   = ps.get("grade", "?")
        reasons = ps.get("reasons", [])

        GRADE_COLORS = {"A": C_GREEN, "B": C_GREEN, "C": C_YELLOW, "D": C_YELLOW, "F": C_RED}
        color = GRADE_COLORS.get(grade, C_TEXT)

        # ── Overview card ──
        ov = tk.Frame(inner, bg=C_SURFACE, padx=20, pady=18)
        ov.pack(fill="x", padx=16, pady=(14, 0))
        tk.Label(ov, text="Privacy Score",
                 bg=C_SURFACE, fg=C_MAUVE,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 8))

        row = tk.Frame(ov, bg=C_SURFACE)
        row.pack(anchor="w")
        tk.Label(row, text=f"{score}",
                 bg=C_SURFACE, fg=color,
                 font=("Segoe UI", 52, "bold")).pack(side="left")
        tk.Label(row, text="/100",
                 bg=C_SURFACE, fg=C_OVERLAY,
                 font=("Segoe UI", 20)).pack(side="left", anchor="s", pady=(0, 10))
        badge = tk.Frame(row, bg=color, padx=12, pady=6)
        badge.pack(side="left", padx=(20, 0), anchor="center")
        tk.Label(badge, text=grade,
                 bg=color, fg=C_BASE,
                 font=("Segoe UI", 24, "bold")).pack()

        # progress bar
        bar_outer = tk.Frame(ov, bg=C_MANTLE, height=16)
        bar_outer.pack(fill="x", pady=(12, 4))
        bar_inner = tk.Frame(bar_outer, bg=color, height=16)
        bar_inner.place(relwidth=max(0.02, score / 100), relheight=1.0)

        tk.Label(ov, text=f"Score: {score}/100  |  Grade: {grade}",
                 bg=C_SURFACE, fg=C_OVERLAY,
                 font=("Segoe UI", 9)).pack(anchor="w")

        # ── Deduction reasons ──
        tk.Frame(inner, bg=C_BASE, height=10).pack()
        rf = tk.Frame(inner, bg=C_SURFACE, padx=18, pady=12)
        rf.pack(fill="x", padx=16, pady=(0, 6))
        if reasons:
            tk.Label(rf, text="Score deductions:",
                     bg=C_SURFACE, fg=C_MAUVE,
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))
            for reason in reasons:
                row2 = tk.Frame(rf, bg=C_SURFACE)
                row2.pack(fill="x", pady=2)
                tk.Label(row2, text="–", bg=C_SURFACE, fg=C_RED,
                         font=("Segoe UI", 11, "bold")).pack(side="left", padx=(0, 8))
                tk.Label(row2, text=reason, bg=C_SURFACE, fg=C_TEXT,
                         font=("Segoe UI", 10),
                         wraplength=680, justify="left").pack(side="left", anchor="w")
        else:
            tk.Label(rf,
                     text="✓  No deductions – the site meets all checked criteria.",
                     bg=C_SURFACE, fg=C_GREEN,
                     font=("Segoe UI", 10)).pack(anchor="w")

        # disclaimer
        tk.Frame(inner, bg=C_BASE, height=8).pack()
        tk.Label(inner,
                 text=(
                     "⚠  Privacy Score is an automatically computed rating and does not "
                     "constitute GDPR compliance certification. The score is based on "
                     "network traffic analysis, detected trackers, cookie flags and GDPR findings."
                 ),
                 bg=C_BASE, fg=C_OVERLAY,
                 font=("Segoe UI", 9),
                 wraplength=760, justify="left").pack(padx=16, pady=(0, 16), anchor="w")

    # ── Cookie Details tab ───────────────────
    def _cookie_details_tab(self, parent, r: dict):
        cook = r.get("cookies", {})

        style = ttk.Style()
        inner_nb = ttk.Notebook(parent)
        inner_nb.pack(fill="both", expand=True)

        for key, label, icon in [
            ("accept_cookie_details",    "After ACCEPTING",  "🔴"),
            ("necessary_cookie_details", "Necessary only",   "🟡"),
            ("reject_cookie_details",    "After REJECTING",  "🟢"),
        ]:
            details = cook.get(key, [])
            tf = tk.Frame(inner_nb, bg=C_BASE)
            inner_nb.add(tf, text=f"  {icon}  {label} ({len(details)})  ")
            self._render_cookie_table(tf, details)

    def _render_cookie_table(self, parent, cookies: list):
        """Render cookie list as a coloured scrollable text table."""
        txt = scrolledtext.ScrolledText(
            parent,
            font=("Consolas", 9),
            bg=C_MANTLE, fg=C_TEXT,
            relief="flat",
            state="normal",
            wrap="none",
        )
        txt.pack(fill="both", expand=True, padx=4, pady=4)

        txt.tag_config("header",   foreground=C_MAUVE)
        txt.tag_config("sep",      foreground=C_OVERLAY)
        txt.tag_config("domain",   foreground=C_CYAN)
        txt.tag_config("company",  foreground=C_PINK)
        txt.tag_config("expiry",   foreground=C_YELLOW)
        txt.tag_config("ok",       foreground=C_GREEN)
        txt.tag_config("warn",     foreground=C_RED)
        txt.tag_config("samesite", foreground=C_BLUE)

        if not cookies:
            txt.insert("end", "  No cookies in this scenario.\n")
            txt.configure(state="disabled")
            return

        hdr = (
            f"  {'Name':<30} {'Domain':<26} {'Company':<24} "
            f"{'Expires':<22} {'Sec':<5} {'HttpOnly':<9} SameSite\n"
        )
        sep = (
            f"  {'─'*30} {'─'*26} {'─'*24} "
            f"{'─'*22} {'─'*5} {'─'*9} {'─'*10}\n"
        )
        txt.insert("end", hdr,  "header")
        txt.insert("end", sep,  "sep")

        for d in cookies:
            name     = (d.get("name",       "") or "?")[:29]
            domain   = (d.get("domain",     "") or "?")[:25]
            company  = (d.get("company",    "") or "–")[:23]
            expiry   = (d.get("expiry_str", "") or "?")[:21]
            secure   = "✓" if d.get("secure")   else "✗"
            httponly = "✓" if d.get("httpOnly") else "✗"
            samesite = (d.get("sameSite",   "") or "?")[:10]

            sec_tag  = "ok"   if d.get("secure")   else "warn"
            http_tag = "ok"   if d.get("httpOnly") else "warn"

            txt.insert("end", f"  {name:<30} ")
            txt.insert("end", f"{domain:<26} ", "domain")
            txt.insert("end", f"{company:<24} ", "company")
            txt.insert("end", f"{expiry:<22} ", "expiry")
            txt.insert("end", f"{secure:<5} ", sec_tag)
            txt.insert("end", f"{httponly:<9} ", http_tag)
            txt.insert("end", f"{samesite}\n", "samesite")

        txt.configure(state="disabled")

    # ── RODO / GDPR tab ──────────────────────
    def _gdpr_tab(self, parent, gdpr: dict):
        _, inner = self._scrollable(parent)

        if not gdpr:
            tk.Label(inner,
                     text="No GDPR data (old analysis file or analysis not yet run).",
                     bg=C_BASE, fg=C_OVERLAY, font=("Segoe UI", 10),
                     wraplength=700, justify="left").pack(padx=20, pady=20, anchor="w")
            return

        overall   = gdpr.get("overall_risk", "NONE")
        counts    = gdpr.get("severity_counts", {})
        compliant = gdpr.get("compliant", True)

        RISK_COLORS = {
            "HIGH":   C_RED,
            "MEDIUM": C_YELLOW,
            "LOW":    C_GREEN,
            "NONE":   C_GREEN,
        }
        RISK_LABELS = {
            "HIGH":   "🔴  HIGH",
            "MEDIUM": "🟡  MEDIUM",
            "LOW":    "🟢  LOW",
            "NONE":   "✅  No violations",
        }
        SEV_COLORS = {"HIGH": C_RED, "MEDIUM": C_YELLOW, "LOW": C_GREEN}

        # ── Overview card ──
        ov = tk.Frame(inner, bg=C_SURFACE, padx=18, pady=14)
        ov.pack(fill="x", padx=16, pady=(12, 0))

        risk_color = RISK_COLORS.get(overall, C_TEXT)
        tk.Label(ov, text="Overall GDPR risk level",
                 bg=C_SURFACE, fg=C_MAUVE,
                 font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w",
                                                     columnspan=2, pady=(0, 8))

        tk.Label(ov, text=RISK_LABELS.get(overall, overall),
                 bg=C_SURFACE, fg=risk_color,
                 font=("Segoe UI", 14, "bold")).grid(row=1, column=0, sticky="w",
                                                      padx=(0, 30))

        for i, (label, sev) in enumerate([
            ("High", "HIGH"), ("Medium", "MEDIUM"), ("Low", "LOW")
        ]):
            cnt = counts.get(sev, 0)
            col = SEV_COLORS[sev] if cnt else C_OVERLAY
            badge = tk.Frame(ov, bg=col, padx=8, pady=4)
            badge.grid(row=1, column=i + 1, padx=4)
            tk.Label(badge, text=str(cnt),
                     bg=col, fg=C_BASE if cnt else C_BASE,
                     font=("Segoe UI", 12, "bold")).pack()
            tk.Label(ov, text=label,
                     bg=C_SURFACE, fg=C_OVERLAY,
                     font=("Segoe UI", 8)).grid(row=2, column=i + 1)

        if compliant:
            tk.Label(ov,
                     text="✓  No potential GDPR violations detected based on "
                          "network traffic analysis.",
                     bg=C_SURFACE, fg=C_GREEN,
                     font=("Segoe UI", 10),
                     wraplength=700, justify="left").grid(
                row=3, column=0, columnspan=5, sticky="w", pady=(10, 0)
            )

        # ── Individual violations ──
        violations = gdpr.get("violations", [])
        if not violations:
            return

        tk.Frame(inner, bg=C_BASE, height=6).pack()

        for v in violations:
            sev   = v.get("severity", "LOW")
            color = SEV_COLORS.get(sev, C_TEXT)

            card = tk.Frame(inner, bg=C_SURFACE, padx=18, pady=12,
                            highlightbackground=color, highlightthickness=2)
            card.pack(fill="x", padx=16, pady=(6, 0))

            # Header row
            hrow = tk.Frame(card, bg=C_SURFACE)
            hrow.pack(fill="x")

            sev_badge = tk.Frame(hrow, bg=color, padx=6, pady=2)
            sev_badge.pack(side="left", padx=(0, 8))
            tk.Label(sev_badge, text=sev,
                     bg=color, fg=C_BASE,
                     font=("Segoe UI", 8, "bold")).pack()

            tk.Label(hrow, text=v.get("title", ""),
                     bg=C_SURFACE, fg=C_TEXT,
                     font=("Segoe UI", 11, "bold")).pack(side="left")

            # Article
            tk.Label(card,
                     text=f"Legal basis: {v.get('article', '')}",
                     bg=C_SURFACE, fg=C_MAUVE,
                     font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))

            # Description
            tk.Label(card,
                     text=v.get("description", ""),
                     bg=C_SURFACE, fg=C_TEXT,
                     font=("Segoe UI", 10),
                     wraplength=740, justify="left").pack(anchor="w", pady=(4, 0))

            # Evidence list
            evidence = v.get("evidence", [])
            if evidence:
                ef = tk.Frame(card, bg=C_MANTLE, padx=10, pady=6)
                ef.pack(fill="x", pady=(8, 0))
                tk.Label(ef, text="Evidence:",
                         bg=C_MANTLE, fg=C_OVERLAY,
                         font=("Segoe UI", 9, "bold")).pack(anchor="w")
                for item in evidence[:15]:
                    tk.Label(ef, text=f"  • {item}",
                             bg=C_MANTLE, fg=C_CYAN,
                             font=("Consolas", 9),
                             anchor="w").pack(fill="x")
                if len(evidence) > 15:
                    tk.Label(ef,
                             text=f"  … and {len(evidence)-15} more (see JSON tab)",
                             bg=C_MANTLE, fg=C_OVERLAY,
                             font=("Segoe UI", 9)).pack(anchor="w")

        # Disclaimer
        tk.Frame(inner, bg=C_BASE, height=8).pack()
        tk.Label(inner,
                 text=(
                     "⚠  The above results are an automated analysis of network traffic and "
                     "do not constitute legal advice. An accurate GDPR compliance assessment "
                     "requires a legal analysis covering the site's full privacy policy."
                 ),
                 bg=C_BASE, fg=C_OVERLAY,
                 font=("Segoe UI", 9),
                 wraplength=760, justify="left").pack(padx=16, pady=(0, 16), anchor="w")

    # ── Fingerprinting tab ────────────────────
    def _fingerprinting_tab(self, parent, fp: dict):
        _, inner = self._scrollable(parent)

        if not fp:
            tk.Label(inner,
                     text="No fingerprinting data (old analysis file or analysis not yet run).",
                     bg=C_BASE, fg=C_OVERLAY, font=("Segoe UI", 10),
                     wraplength=700, justify="left").pack(padx=20, pady=20, anchor="w")
            return

        risk = fp.get("risk", "NONE")
        RISK_COLORS = {"HIGH": C_RED, "MEDIUM": C_YELLOW, "LOW": C_GREEN, "NONE": C_GREEN}
        RISK_LABELS = {"HIGH": "🔴  HIGH", "MEDIUM": "🟡  MEDIUM",
                       "LOW":  "🟢  LOW",  "NONE":  "✅  None detected"}
        risk_color = RISK_COLORS.get(risk, C_TEXT)

        # Overview card
        ov = tk.Frame(inner, bg=C_SURFACE, padx=18, pady=14)
        ov.pack(fill="x", padx=16, pady=(12, 0))
        tk.Label(ov, text="Browser Fingerprinting Risk",
                 bg=C_SURFACE, fg=C_MAUVE,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 6))
        tk.Label(ov, text=RISK_LABELS.get(risk, risk),
                 bg=C_SURFACE, fg=risk_color,
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")

        # Details
        tk.Frame(inner, bg=C_BASE, height=8).pack()
        df = tk.Frame(inner, bg=C_SURFACE, padx=18, pady=12)
        df.pack(fill="x", padx=16, pady=(0, 6))
        tk.Label(df, text="Findings", bg=C_SURFACE, fg=C_MAUVE,
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))
        for line in fp.get("details", ["No indicators found."]):
            tk.Label(df, text=f"  • {line}", bg=C_SURFACE, fg=C_TEXT,
                     font=("Segoe UI", 10),
                     wraplength=740, justify="left").pack(anchor="w", pady=1)

        # Domain list
        domains = fp.get("domains", [])
        if domains:
            tk.Frame(inner, bg=C_BASE, height=4).pack()
            dmf = tk.Frame(inner, bg=C_SURFACE, padx=18, pady=10)
            dmf.pack(fill="x", padx=16, pady=(0, 6))
            tk.Label(dmf, text=f"Known fingerprinting services contacted ({len(domains)})",
                     bg=C_SURFACE, fg=C_MAUVE,
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))
            for d in domains:
                tk.Label(dmf, text=f"  🔴 {d}", bg=C_SURFACE, fg=C_RED,
                         font=("Consolas", 10)).pack(anchor="w")

        # JS signals
        signals = fp.get("signals", [])
        if signals:
            tk.Frame(inner, bg=C_BASE, height=4).pack()
            sf = tk.Frame(inner, bg=C_SURFACE, padx=18, pady=10)
            sf.pack(fill="x", padx=16, pady=(0, 6))
            tk.Label(sf, text=f"Fingerprinting JS APIs detected ({len(signals)})",
                     bg=C_SURFACE, fg=C_MAUVE,
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))
            for s in signals[:20]:
                tk.Label(sf, text=f"  · {s}", bg=C_SURFACE, fg=C_YELLOW,
                         font=("Consolas", 9)).pack(anchor="w")

        # Disclaimer
        tk.Frame(inner, bg=C_BASE, height=8).pack()
        tk.Label(inner,
                 text=("⚠  Fingerprinting detection is heuristic. False positives are possible "
                       "– a detected API call does not necessarily mean the site tracks you. "
                       "Results are for informational purposes only."),
                 bg=C_BASE, fg=C_OVERLAY,
                 font=("Segoe UI", 9),
                 wraplength=760, justify="left").pack(padx=16, pady=(0, 16), anchor="w")

    # ── Ranking tab ───────────────────────────
    def _ranking_tab(self, parent, batch: list):
        _, inner = self._scrollable(parent)

        GRADE_ICON = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟡", "F": "🔴"}
        RISK_COLOR = {"HIGH": C_RED, "MEDIUM": C_YELLOW, "LOW": C_GREEN, "NONE": C_GREEN}
        FP_COLOR   = {"HIGH": C_RED, "MEDIUM": C_YELLOW, "LOW": C_GREEN, "NONE": C_GREEN}

        tk.Label(inner, text=f"  Session ranking – {len(batch)} site(s) analysed",
                 bg=C_BASE, fg=C_MAUVE,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=16, pady=(12, 4))

        ok   = [r for r in batch if r.get("score") is not None]
        fail = [r for r in batch if r.get("score") is None]
        ok.sort(key=lambda r: r["score"], reverse=True)
        ranked = ok + fail

        for i, r in enumerate(ranked, 1):
            url_str   = r.get("url", "?")
            score     = r.get("score")
            grade     = r.get("grade", "?")
            gdpr_risk = r.get("gdpr_risk", "?")
            fp_risk   = r.get("fp_risk",   "?")
            error     = r.get("error")

            card = tk.Frame(inner, bg=C_SURFACE, padx=14, pady=8)
            card.pack(fill="x", padx=16, pady=(0, 4))

            # rank badge
            badge = tk.Frame(card, bg=C_OVERLAY, padx=6, pady=4)
            badge.pack(side="left", padx=(0, 10))
            tk.Label(badge, text=f"#{i}",
                     bg=C_OVERLAY, fg=C_BASE,
                     font=("Segoe UI", 11, "bold")).pack()

            info = tk.Frame(card, bg=C_SURFACE)
            info.pack(side="left", fill="x", expand=True)

            tk.Label(info, text=url_str,
                     bg=C_SURFACE, fg=C_TEXT,
                     font=("Segoe UI", 11, "bold")).pack(anchor="w")

            if error:
                tk.Label(info, text=f"❌  Error: {error[:80]}",
                         bg=C_SURFACE, fg=C_RED,
                         font=("Segoe UI", 9)).pack(anchor="w")
            else:
                gc = GRADE_ICON.get(grade, "•")
                score_str = f"{gc} Score: {score}/100  Grade: {grade}"
                gdpr_col  = RISK_COLOR.get(gdpr_risk, C_TEXT)
                fp_col    = FP_COLOR.get(fp_risk, C_TEXT)

                row2 = tk.Frame(info, bg=C_SURFACE)
                row2.pack(anchor="w")
                tk.Label(row2, text=score_str,
                         bg=C_SURFACE, fg=C_GREEN if score and score >= 70 else C_YELLOW,
                         font=("Segoe UI", 10)).pack(side="left", padx=(0, 16))
                tk.Label(row2, text=f"GDPR: {gdpr_risk}",
                         bg=C_SURFACE, fg=gdpr_col,
                         font=("Segoe UI", 10)).pack(side="left", padx=(0, 16))
                tk.Label(row2, text=f"FP: {fp_risk}",
                         bg=C_SURFACE, fg=fp_col,
                         font=("Segoe UI", 10)).pack(side="left")

        # Best / worst summary
        if ok:
            tk.Frame(inner, bg=C_BASE, height=8).pack()
            sf = tk.Frame(inner, bg=C_SURFACE, padx=14, pady=10)
            sf.pack(fill="x", padx=16, pady=(0, 12))
            tk.Label(sf, text="Summary", bg=C_SURFACE, fg=C_MAUVE,
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 4))
            tk.Label(sf,
                     text=f"🏆 Best  : {ok[0]['url']}  (score {ok[0]['score']}, grade {ok[0]['grade']})",
                     bg=C_SURFACE, fg=C_GREEN, font=("Segoe UI", 10)).pack(anchor="w")
            if len(ok) > 1:
                tk.Label(sf,
                         text=f"⚠️  Worst : {ok[-1]['url']}  (score {ok[-1]['score']}, grade {ok[-1]['grade']})",
                         bg=C_SURFACE, fg=C_RED, font=("Segoe UI", 10)).pack(anchor="w")

    # ── JSON tab ─────────────────────────────
    def _json_tab(self, parent, result: dict):
        txt = scrolledtext.ScrolledText(
            parent, font=("Consolas", 9),
            bg=C_MANTLE, fg=C_GREEN,
            relief="flat", state="normal",
        )
        txt.pack(fill="both", expand=True, padx=4, pady=4)
        txt.insert("end", json.dumps(result, indent=2, ensure_ascii=False))
        txt.configure(state="disabled")

    # ── misc ─────────────────────────────────
    def _open_folder(self):
        if self._outdir and os.path.isdir(self._outdir):
            subprocess.Popen(["xdg-open", self._outdir])

    def _open_pdf(self):
        if self._outdir:
            pdf = os.path.join(self._outdir, "report_card.pdf")
            if os.path.isfile(pdf):
                subprocess.Popen(["xdg-open", pdf])


# ════════════════════════════════════════════
#  Entry point
# ════════════════════════════════════════════

if __name__ == "__main__":
    # ensure packages installed before GUI starts importing them
    try:
        from ciaho import _ensure_packages
        _ensure_packages()
    except Exception:
        pass
    CiahoGui().mainloop()
