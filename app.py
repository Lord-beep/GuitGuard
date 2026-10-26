from __future__ import annotations

import queue
import threading
import tkinter as tk

from pathlib import Path
from tkinter import ttk, messagebox

from core import (
    basic_code_safety_check,
    clone_repository,
    scan_with_windows_defender,
    scan_with_virustotal,
    scan_with_yara,
    validate_github_url,
)


APP_NAME = "GitGuard — Scanner Seguro"
APP_DIR = Path(__file__).resolve().parent
BASE_DIR = APP_DIR / "Projetos_Descarregados"
RULES_PATH = APP_DIR / "regras.yar"


class ModernGitGuard:
    BG = "#1e1e2e"
    PANEL = "#313244"
    TEXT = "#cdd6f4"
    MUTED = "#a6adc8"
    BLUE = "#89b4fa"
    GREEN = "#a6e3a1"
    RED = "#f38ba8"
    YELLOW = "#f9e2af"

    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("760x700")
        self.root.minsize(620, 560)
        self.root.configure(bg=self.BG)

        self.events = queue.Queue()
        self.busy = False
        self.closing = False
        self.cancel_event = threading.Event()
        self.worker_thread = None

        self._setup_style()
        self._build_ui()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._process_events)

    def _setup_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(
            "TLabel",
            background=self.BG,
            foreground=self.TEXT,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Title.TLabel",
            background=self.BG,
            foreground="#cba6f7",
            font=("Segoe UI", 19, "bold"),
        )
        style.configure(
            "Subtitle.TLabel",
            background=self.BG,
            foreground=self.MUTED,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Modern.TButton",
            background=self.BLUE,
            foreground="#11111b",
            font=("Segoe UI", 10, "bold"),
            padding=9,
        )
        style.map(
            "Modern.TButton",
            background=[
                ("disabled", "#45475a"),
                ("active", "#b4befe"),
            ],
        )

    def _build_ui(self):
        frame = tk.Frame(self.root, bg=self.BG)
        frame.pack(fill="both", expand=True, padx=24, pady=20)

        ttk.Label(
            frame,
            text="🛡️ GitGuard",
            style="Title.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            frame,
            text="Triagem de segurança de repositórios Git não confiáveis",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(3, 16))

        ttk.Label(
            frame,
            text="URL HTTPS de um repositório GitHub público",
        ).pack(anchor="w", pady=(0, 5))

        self.url_entry = tk.Entry(
            frame,
            font=("Segoe UI", 10),
            bg=self.PANEL,
            fg=self.TEXT,
            insertbackground=self.TEXT,
            relief="flat",
        )
        self.url_entry.pack(fill="x", ipady=8, pady=(0, 12))

        ttk.Label(
            frame,
            text="Chave API VirusTotal (opcional)",
        ).pack(anchor="w", pady=(0, 5))

        self.api_entry = tk.Entry(
            frame,
            font=("Segoe UI", 10),
            bg=self.PANEL,
            fg=self.TEXT,
            insertbackground=self.TEXT,
            show="*",
            relief="flat",
        )
        self.api_entry.pack(fill="x", ipady=8, pady=(0, 14))

        buttons = tk.Frame(frame, bg=self.BG)
        buttons.pack(fill="x", pady=(0, 12))

        self.scan_button = ttk.Button(
            buttons,
            text="Analisar repositório",
            style="Modern.TButton",
            command=self.process_repo,
        )
        self.scan_button.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 5),
        )

        self.cancel_button = ttk.Button(
            buttons,
            text="Cancelar",
            command=self.cancel_scan,
            state="disabled",
        )
        self.cancel_button.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(5, 0),
        )

        self.progress = ttk.Progressbar(
            frame,
            mode="indeterminate",
        )
        self.progress.pack(fill="x", pady=(0, 12))

        ttk.Label(
            frame,
            text="Registo de segurança",
        ).pack(anchor="w", pady=(0, 5))

        log_frame = tk.Frame(frame, bg=self.PANEL)
        log_frame.pack(fill="both", expand=True)

        self.log_text = tk.Text(
            log_frame,
            height=14,
            wrap="word",
            font=("Consolas", 9),
            bg="#11111b",
            fg=self.TEXT,
            insertbackground=self.TEXT,
            relief="flat",
            padx=10,
            pady=10,
            state="disabled",
        )

        scrollbar = ttk.Scrollbar(
            log_frame,
            orient="vertical",
            command=self.log_text.yview,
        )
        self.log_text.configure(yscrollcommand=scrollbar.set)

        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.status_var = tk.StringVar(
            value="Estado: à espera de um repositório"
        )

        ttk.Label(
            frame,
            textvariable=self.status_var,
        ).pack(anchor="w", pady=(10, 0))

        ttk.Label(
            frame,
            text=(
                "Não instala dependências nem executa intencionalmente "
                "o código do repositório. A análise não garante segurança."
            ),
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(5, 0))

    # --------------------------------------------------------
    # INTERFACE E REGISTO
    # --------------------------------------------------------

    def log(self, message, color=None):
        self.log_text.configure(state="normal")

        start = self.log_text.index("end-1c")
        self.log_text.insert("end", str(message) + "\n")

        if color:
            tag = f"color_{color}"
            self.log_text.tag_configure(tag, foreground=color)
            self.log_text.tag_add(tag, start, "end-1c")

        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _emit(self, kind, value=None):
        self.events.put((kind, value))

    # --------------------------------------------------------
    # INICIAR ANÁLISE
    # --------------------------------------------------------

    def process_repo(self):
        if self.busy:
            return

        try:
            repo_url, repo_name = validate_github_url(
                self.url_entry.get()
            )
        except ValueError as exc:
            messagebox.showerror(
                "URL inválido",
                str(exc),
                parent=self.root,
            )
            return

        try:
            if BASE_DIR.is_symlink():
                raise ValueError(
                    "A pasta de destino não pode ser uma ligação simbólica."
                )

            BASE_DIR.mkdir(parents=True, exist_ok=True)
            base = BASE_DIR.resolve()

            target = base / repo_name

            if target.exists() or target.is_symlink():
                raise ValueError(
                    "O destino já existe. Não será sobrescrito."
                )

        except (OSError, ValueError) as exc:
            messagebox.showerror(
                "Destino inválido",
                str(exc),
                parent=self.root,
            )
            return

        api_key = self.api_entry.get().strip() or None

        self.cancel_event.clear()
        self.busy = True

        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")

        self.progress.start(10)
        self.status_var.set("Estado: clonagem e análise em curso")

        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

        self.log(f"Repositório: {repo_url}")
        self.log(f"Destino: {target}")
        self.log("Clonagem sem submódulos.")
        self.log("Não serão instaladas dependências.")
        self.log("A análise pode demorar alguns minutos.")

        self.worker_thread = threading.Thread(
            target=self._worker,
            args=(repo_url, target, api_key),
            daemon=True,
        )
        self.worker_thread.start()

    def cancel_scan(self):
        if not self.busy:
            return

        self.cancel_event.set()
        self.cancel_button.configure(state="disabled")
        self.status_var.set(
            "Estado: cancelamento solicitado"
        )
        self.log(
            "Cancelamento solicitado. A operação atual pode demorar "
            "a terminar."
        )

    # --------------------------------------------------------
    # TRABALHO EM SEGUNDO PLANO
    # --------------------------------------------------------

    def _worker(self, repo_url, target, api_key):
        results = []
        cloned = False

        try:
            if self.cancel_event.is_set():
                raise InterruptedError("Operação cancelada.")

            self._emit("log", "A clonar o repositório...")

            clone_repository(
                repo_url,
                target,
                timeout=180,
                cancel_event=self.cancel_event,
            )
            cloned = True

            self._emit("log", "Clonagem concluída.")

            scanners = [
                (
                    "Análise estática",
                    lambda: basic_code_safety_check(str(target)),
                ),
                (
                    "Windows Defender",
                    lambda: scan_with_windows_defender(str(target)),
                ),
                (
                    "VirusTotal",
                    lambda: scan_with_virustotal(
                        str(target),
                        api_key,
                        self.cancel_event,
                    ),
                ),
                (
                    "YARA",
                    lambda: scan_with_yara(
                        str(target),
                        str(RULES_PATH),
                    ),
                ),
            ]

            for name, scanner in scanners:
                if self.cancel_event.is_set():
                    results.append((name, "unknown"))
                    self._emit(
                        "result",
                        (
                            name,
                            "unknown",
                            "Verificação cancelada ou não iniciada.",
                        ),
                    )
                    continue

                self._emit("log", f"A executar: {name}...")

                try:
                    status, detail = scanner()

                    if status not in {
                        "clean",
                        "suspicious",
                        "threat",
                        "unknown",
                    }:
                        status = "unknown"
                        detail = "O motor devolveu um estado inválido."

                except Exception as exc:
                    status = "unknown"
                    detail = (
                        f"Erro inesperado neste motor: "
                        f"{type(exc).__name__}: {exc}"
                    )

                results.append((name, status))
                self._emit(
                    "result",
                    (name, status, detail),
                )

            statuses = [status for _, status in results]

            if "threat" in statuses or "suspicious" in statuses:
                final_status = "SUSPEITO — NÃO EXECUTAR"
                final_color = self.RED

            elif self.cancel_event.is_set():
                final_status = "CANCELADO — NÃO VALIDADO"
                final_color = self.YELLOW

            elif statuses and all(
                status == "clean" for status in statuses
            ):
                final_status = (
                    "SEM DETEÇÕES — NÃO É GARANTIA DE SEGURANÇA"
                )
                final_color = self.GREEN

            else:
                final_status = (
                    "INCONCLUSIVO — NÃO CONSIDERAR SEGURO"
                )
                final_color = self.YELLOW

            self._emit(
                "finished",
                (final_status, final_color),
            )

        except InterruptedError:
            self._emit(
                "finished",
                (
                    "CANCELADO — REPOSITÓRIO NÃO VALIDADO",
                    self.YELLOW,
                ),
            )

        except Exception as exc:
            self._emit(
                "log",
                f"Falha: {type(exc).__name__}: {exc}",
            )

            self._emit(
                "finished",
                (
                    "FALHA — REPOSITÓRIO NÃO VALIDADO",
                    self.RED,
                ),
            )

        finally:
            if self.cancel_event.is_set():
                self._emit(
                    "log",
                    "A operação terminou com um pedido de cancelamento.",
                )

            if not cloned:
                self._emit(
                    "log",
                    "A clonagem não foi concluída; não foi aprovado "
                    "qualquer repositório.",
                )

    # --------------------------------------------------------
    # PROCESSAR EVENTOS NA THREAD PRINCIPAL
    # --------------------------------------------------------

    def _process_events(self):
        if self.closing:
            return

        try:
            while True:
                kind, value = self.events.get_nowait()

                if kind == "log":
                    self.log(value)

                elif kind == "result":
                    name, status, detail = value

                    colors = {
                        "clean": self.GREEN,
                        "threat": self.RED,
                        "suspicious": self.RED,
                        "unknown": self.YELLOW,
                    }

                    self.log(
                        f"[{status.upper()}] {name}",
                        colors.get(status, self.YELLOW),
                    )
                    self.log(detail)

                elif kind == "finished":
                    status, color = value

                    self.log(f"\nRESULTADO: {status}", color)
                    self.status_var.set(f"Estado: {status}")

                    self.progress.stop()
                    self.scan_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")

                    self.busy = False
                    self.worker_thread = None

        except queue.Empty:
            pass

        self.root.after(100, self._process_events)

    # --------------------------------------------------------
    # FECHAR A APLICAÇÃO
    # --------------------------------------------------------

    def _on_close(self):
        if self.busy:
            close = messagebox.askyesno(
                "Análise em curso",
                "A análise pode não terminar imediatamente. "
                "Queres solicitar o cancelamento e fechar a janela?",
                parent=self.root,
            )

            if not close:
                return

            self.cancel_event.set()

        self.closing = True
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ModernGitGuard(root)
    root.mainloop()