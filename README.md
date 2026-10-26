# 🚀 GitGuard

O **GitGuard** (SafeGit) é uma aplicação desenvolvida em Python que disponibiliza uma interface gráfica amigável para a interação e gestão de repositórios Git.

---

## ✨ Funcionalidades

- 🖥️ **Interface Gráfica Utilizável**: Interface construída com Tkinter e componentes TTK.
- 🔀 **Integração com Git**: Operações de controlo de versões integradas através da biblioteca GitPython.
- ⚡ **Execução de Comandos Internos**: Gestão de processos e operações de sistema.

---

## 🛠️ Tecnologias

| Tecnologia | Utilização |
|---|---|
| Python | Linguagem principal |
| Tkinter | Interface gráfica de utilizador (GUI) |
| GitPython (`git`) | Integração e manipulação de repositórios Git |
| PyInstaller | Empacotamento e compilação de executáveis |

---

## ⚙️ Instalação

### Pré-requisitos

- Python 3.x instalado no sistema.
- Git instalado e configurado no ambiente.

### Instalar dependências

Para instalar a biblioteca de integração com o Git, execute:

```bash
pip install GitPython
```

---

## ▶️ Execução

Para iniciar a aplicação a partir do código fonte:

```bash
python gitguard.py
```

---

## 📁 Estrutura do projeto

```text
safegit/
├── gitguard.py
└── core.py
```

---

## 📦 Versão portátil / Build

O projeto inclui suporte para geração de executáveis autónomos através do PyInstaller.

Para compilar a aplicação:

```bash
pyinstaller gitguard.py
```
---

## 👤 Autor

**Lord-beep**

---

## ⭐ Projeto

Se este projeto for útil, considere deixar uma estrela no repositório!
