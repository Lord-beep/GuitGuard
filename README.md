# 🚀 GitGuard — Scanner Seguro

O **GitGuard** é uma ferramenta de triagem de segurança com interface gráfica concebida para analisar repositórios Git públicos antes de os executar ou inspecionar localmente. A aplicação efetua o descarregamento isolado do código-fonte e submete-o a múltiplos motores de análise para identificar potenciais ameaças.

---

## ✨ Funcionalidades

- 🛡️ **Clonagem segura**: Clona repositórios públicos via HTTPS para uma pasta isolada, sem descarregar submódulos e sem instalar dependências.
- 🔍 **Análise estática**: Inspeciona o código do repositório em busca de padrões e comportamentos de risco.
- 💻 **Integração com Windows Defender**: Realiza varreduras locais recorrendo ao motor do Windows Defender.
- 🌐 **Inspecção VirusTotal**: Suporte opcional para verificação de ficheiros através da API do VirusTotal.
- 🎯 **Regras YARA**: Utilização do ficheiro de regras `regras.yar` para deteção de assinaturas maliciosas.
- 📊 **Registo em tempo real**: Exibição detalhada de alertas, estados de verificação e diagnósticos finais numa interface moderna.
- 🛑 **Controlo de execução**: Possibilidade de interromper o processo de clonagem e verificação a qualquer momento.

---

## 🛠️ Tecnologias

| Tecnologia | Utilização |
|---|---|
| Python | Linguagem de programação principal |
| Tkinter / ttk | Interface gráfica do utilizador |
| YARA | Motor de deteção baseado em regras de assinaturas |
| Windows Defender | Verificação de segurança local no sistema operativo |
| VirusTotal API | Serviço externo de verificação de ameaças na nuvem |

---

## ⚙️ Instalação

1. Garanta que tem o Python instalado no sistema operativo.
2. Certifique-se de que os ficheiros do projeto se encontram na mesma pasta:
   - `app.py`
   - `core.py`
   - `regras.yar`

---

## ▶️ Execução

Para iniciar a aplicação gráfica, execute no terminal:

```bash
python app.py
```

---

## 📖 Como utilizar

1. Inicie a aplicação `GitGuard`.
2. No campo **URL HTTPS**, insira a hiperligação de um repositório público do GitHub.
3. No campo **Chave API VirusTotal** (opcional), insira a sua chave caso pretenda ativar a verificação na nuvem.
4. Clique em **Analisar repositório**.
5. Acompanhe o progresso e consulte os resultados no painel **Registo de segurança**.

---

## 📁 Estrutura do projeto

```text
.
├── app.py
├── core.py
├── regras.yar
└── Projetos_Descarregados/
```

---

## 🧠 Como funciona

O GitGuard executa a verificação por etapas, garantindo que o código descarregado não é executado nem instalado durante o processo:

```text
URL HTTPS do GitHub
        │
        ▼
Clonagem do Repositório
        │
        ├──────────► Análise Estática
        ├──────────► Windows Defender
        ├──────────► VirusTotal (Chave API opcional)
        └──────────► Regras YARA (regras.yar)
        │
        ▼
Resultado de Triagem no Registo
```

---

## 🔒 Segurança

- O GitGuard **não executa intencionalmente** o código do repositório nem instala pacotes ou dependências do projeto analisado.
- Os repositórios analisados são guardados na pasta local `Projetos_Descarregados/`.
- A chave de API do VirusTotal é inserida através de um campo de texto mascarado.

---

## 📦 Versão portátil / Build

É possível gerar uma versão executável autónoma da aplicação recorrendo ao PyInstaller:

```bash
pyinstaller gitguard.py
```
---

## 👤 Autor

**Lord-beep**

---

## ⭐ Projeto

Se este projeto foi útil para a triagem e análise de segurança dos seus repositórios, considere dar uma estrela no GitHub!
