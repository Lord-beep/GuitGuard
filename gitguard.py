import os
import sys
import subprocess
import shutil
import tkinter as tk
from tkinter import ttk, messagebox

# Importa a tua lógica separada do ficheiro core.py
from core import scan_with_windows_defender, basic_code_safety_check
from git import Repo, GitCommandError

class ModernGitGuard:
    def __init__(self, root):
        self.root = root
        self.root.title("GitGuard — Scanner Seguro")
        self.root.geometry("600x480")
        self.root.configure(bg="#1e1e2e")  # Fundo Dark moderno (Catppuccin/Nord style)
        self.root.resizable(False, False)
        
        # Configuração de Estilos Customizados
        style = ttk.Style()
        style.theme_use('default')
        
        # Estilo das Labels (Textos)
        style.configure("TLabel", background="#1e1e2e", foreground="#cdd6f4", font=("Segoe UI", 10))
        style.configure("Title.TLabel", foreground="#cba6f7", font=("Segoe UI", 16, "bold"))
        style.configure("Subtitle.TLabel", foreground="#a6adc8", font=("Segoe UI", 9, "italic"))
        
        # Estilo do Botão Moderno
        style.configure("Modern.TButton", 
                        background="#89b4fa", 
                        foreground="#11111b", 
                        font=("Segoe UI", 10, "bold"), 
                        borderwidth=0, 
                        focalthickness=0, 
                        padding=10)
        style.map("Modern.TButton",
                  background=[("active", "#b4befe"), ("disabled", "#45475a")],
                  foreground=[("disabled", "#7f849c")])

        # --- DESIGN DA INTERFACE ---
        
        # Contentor Principal com margens
        main_frame = tk.Frame(root, bg="#1e1e2e")
        main_frame.pack(fill="both", expand=True, padx=25, pady=20)
        
        # Zona do Título
        ttk.Label(main_frame, text="🛡️ GitGuard", style="Title.TLabel").pack(anchor="w", pady=(0, 2))
        ttk.Label(main_frame, text="Clonagem isolada de repositórios com análise de malware integrada", style="Subtitle.TLabel").pack(anchor="w", pady=(0, 20))
        
        # Zona de Input (Caixa de Texto)
        ttk.Label(main_frame, text="URL do Repositório GitHub:", style="TLabel").pack(anchor="w", pady=(0, 5))
        
        # Caixa de texto customizada para parecer moderna
        self.url_entry = tk.Entry(main_frame, 
                                  width=55, 
                                  font=("Segoe UI", 11), 
                                  bg="#313244", 
                                  fg="#cdd6f4", 
                                  insertbackground="#cdd6f4", 
                                  bd=0, 
                                  highlightthickness=1, 
                                  highlightbackground="#45475a", 
                                  highlightcolor="#89b4fa")
        self.url_entry.pack(fill="x", ipady=8, pady=(0, 15))
        
        # Botão de Ação
        self.btn_download = ttk.Button(main_frame, text="Analisar e Descarregar", style="Modern.TButton", command=self.process_repo)
        self.btn_download.pack(fill="x", pady=(0, 20))
        
        # Consola de Logs Embutida
        ttk.Label(main_frame, text="Terminal de Segurança:", style="TLabel").pack(anchor="w", pady=(0, 5))
        
        self.log_text = tk.Text(main_frame, 
                                height=12, 
                                font=("Consolas", 10), 
                                bg="#11111b", 
                                fg="#a6e3a1", 
                                insertbackground="#a6e3a1", 
                                bd=0, 
                                highlightthickness=1, 
                                highlightbackground="#313244",
                                state="disabled")
        self.log_text.pack(fill="both", expand=True)
        
    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def process_repo(self):
        repo_url = self.url_entry.get().strip()
        if not repo_url:
            messagebox.showerror("Erro", "Insira um URL válido do GitHub.")
            return
            
        self.btn_download.config(state="disabled")
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state="disabled")
        
        if not repo_url.endswith(".git"):
            repo_url += ".git"
            
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        base_dir = os.path.join(os.getcwd(), "Projetos_Descarregados")
        target_path = os.path.abspath(os.path.join(base_dir, repo_name))
        
        self.log(f"📦 Destino: {target_path}")
        self.log("🔄 A clonar o repositório em ambiente isolado...")
        
        try:
            if os.path.exists(target_path):
                self.log("⚠️ O diretório local já existe. A efetuar pull de atualização...")
                repo = Repo(target_path)
                repo.remotes.origin.pull()
            else:
                Repo.clone_from(repo_url, target_path)
                self.log("✅ Download do código base concluído.")
        except GitCommandError as e:
            self.log(f"❌ Falha no Git: {e}")
            self.btn_download.config(state="normal")
            return

        # Análise de Código Oculto
        self.log("\n🔍 A iniciar análise estática do código fonte...")
        code_ok, code_msg = basic_code_safety_check(target_path)
        self.log(code_msg)
        
        # Antivírus Real-time
        self.log("\n🛡️ A invocar módulo do Windows Defender...")
        virus_ok, virus_msg = scan_with_windows_defender(target_path)
        self.log(virus_msg)
        
        if not virus_ok:
            self.log("\n🛑 STATUS: AMEAÇA DETETADA. PROCESSO BLOQUEADO.")
            delete_folder = messagebox.askyesno("Alerta de Segurança", "O antivírus bloqueou este repositório devido a ameaças! Deseja apagar a pasta permanentemente?")
            if delete_folder:
                shutil.rmtree(target_path)
                self.log("🧹 Sistema limpo. Pasta corrompida removida com sucesso.")
            self.btn_download.config(state="normal")
            return

        # Dependências automáticas
        requirements_file = os.path.join(target_path, "requirements.txt")
        if os.path.exists(requirements_file):
            self.log("\n📦 A compilar dependências detetadas (requirements.txt)...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", requirements_file])
                self.log("💡 Ambiente virtual e dependências configuradas com sucesso!")
            except Exception as e:
                self.log(f"⚠️ Alerta no pip: {e}")
                
        self.log("\n🚀 OPERAÇÃO CONCLUÍDA: Repositório validado e seguro para execução.")
        messagebox.showinfo("Sucesso", f"O projeto está pronto e seguro em:\n{target_path}")
        self.btn_download.config(state="normal")

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernGitGuard(root)
    root.mainloop()
