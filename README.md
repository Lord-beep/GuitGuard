# 🛡️ GitGuard (SafeGit)

O **GitGuard** é uma aplicação para Windows desenvolvida em Python que permite realizar uma triagem de segurança de repositórios Git públicos antes de os utilizar. 

A aplicação disponibiliza uma interface gráfica baseada em Tkinter e combina análise estática, Microsoft Defender, VirusTotal e regras YARA para identificar possíveis indicadores de risco.

> ⚠️ **Aviso de segurança:** O GitGuard é uma ferramenta de triagem, não um antivírus completo nem uma sandbox. A ausência de deteções não garante que um repositório seja seguro.

---

## ✨ Funcionalidades

* 🖥️ **Interface gráfica:** construída com Tkinter e TTK.
* 🔗 **Integração com GitHub:** clonagem de repositórios públicos através de HTTPS.
* 🔍 **Análise estática:** identificação de padrões potencialmente suspeitos.
* 🛡️ **Microsoft Defender:** análise antimalware no Windows.
* 🌐 **VirusTotal API v3:** consulta de hashes SHA-256 sem envio automático do conteúdo dos ficheiros.
* 🧬 **YARA:** análise com regras personalizadas.
* 🧵 **Interface responsiva:** operações demoradas executadas numa thread de trabalho.
* ⛔ **Cancelamento:** possibilidade de solicitar a interrupção de uma análise.
* 📋 **Registo de resultados:** apresentação do estado de cada motor de análise.
* 🚫 **Proteção dos ficheiros existentes:** evita utilizar um destino de clonagem já existente.

---

## 🛠️ Tecnologias

| Tecnologia | Utilização |
| :--- | :--- |
| **Python 3** | Linguagem principal |
| **Tkinter / TTK** | Interface gráfica |
| **Git** | Clonagem de repositórios |
| **GitPython** | Integração com Git |
| **yara-python** | Análise com regras YARA |
| **VirusTotal API v3** | Consulta de hashes SHA-256 |
| **Microsoft Defender** | Análise antimalware |
| **PyInstaller** | Criação do executável |

---

## 📥 Instalação

### Opção 1 — Utilizar o executável Windows
1. Acede à página de *Releases* do GitGuard.
2. Descarrega o executável, caso esteja disponível.
3. Guarda o ficheiro no teu computador.
4. Executa `GitGuard.exe`.

*Nota: Se ainda não existir um executável na secção Releases, utiliza a instalação a partir do código-fonte descrita abaixo.*

> 💡 O Windows Defender ou outro software de segurança pode apresentar avisos sobre executáveis desconhecidos. Confirma sempre a origem do ficheiro antes de o executar.

### Opção 2 — Executar a partir do código-fonte

#### Pré-requisitos
* Windows 10 ou Windows 11.
* Python 3.10 ou superior.
* Git instalado e disponível no PATH.
* Ligação à Internet.

#### 1. Clonar o projeto
Abre o CMD ou Git Bash e executa:
```bash
git clone https://github.com/Lord-beep/SafeGuit.git
cd SafeGuit
```

#### 2. Criar um ambiente virtual
```bash
python -m venv .venv
```
Ativa-o no CMD:
```cmd
.venv\Scripts\activate
```

#### 3. Instalar as dependências
```bash
python -m pip install --upgrade pip
python -m pip install GitPython yara-python
```

#### 4. Iniciar a aplicação
```bash
python app.py
```
A interface gráfica do GitGuard deverá abrir numa nova janela.

---

## ▶️ Como utilizar

### 1. Introduzir o URL
No campo do repositório, introduz o endereço HTTPS de um repositório público do GitHub.

**Exemplo:**
```text
https://github.com/octocat/Spoon-Knife
```
Clica em **Analisar repositório** para iniciar a clonagem e a análise.

### 2. Configurar o VirusTotal (opcional)
Para obter uma chave API:
1. Acede ao VirusTotal.
2. Cria uma conta ou inicia sessão.
3. Consulta a tua chave em *My API Key*.
4. Copia a chave para o campo correspondente da aplicação.

> 🔒 O GitGuard consulta hashes SHA-256. Não envia automaticamente o conteúdo dos ficheiros para o VirusTotal. **Nunca publiques a tua chave API no GitHub nem a incluas diretamente no código-fonte.**

### 3. Consultar os resultados
O GitGuard apresenta o resultado de cada motor no registo de segurança.

| Estado | Significado |
| :--- | :--- |
| **CLEAN** | O motor não reportou deteções segundo os critérios utilizados. |
| **SUSPICIOUS** | Foram encontrados padrões que merecem investigação. |
| **THREAT** | Um motor reportou uma possível ameaça. |
| **UNKNOWN** | A análise não pôde ser concluída ou não existem dados suficientes. |

O resultado global pode ser:
* 🔴 **SUSPEITO — NÃO EXECUTAR:** foi encontrada uma deteção ou um indicador suspeito.
* 🟢 **SEM DETEÇÕES:** os motores executados não reportaram deteções, mas isso não garante segurança.
* 🟡 **INCONCLUSIVO:** pelo menos um motor não conseguiu concluir a análise.

*Nota: Um ficheiro cujo hash não é conhecido pelo VirusTotal não deve ser considerado automaticamente seguro ou malicioso.*

### 4. Cancelar uma análise
Utiliza o botão **Cancelar** para solicitar a interrupção da operação atual. O cancelamento pode não ser imediato.

---

## 🧬 Regras YARA

O ficheiro `regras.yar` contém as regras utilizadas pelo motor YARA.

* As regras têm de ser válidas para poderem ser compiladas.
* Se o ficheiro estiver ausente ou não puder ser compilado, a análise deve ser considerada inconclusiva.
* As regras podem gerar falsos positivos e não detetam todas as ameaças.
* Uma regra de demonstração, como `GitGuard_Test_Marker`, serve apenas para testar a integração.
* Podes adicionar regras próprias ou de fontes reconhecidas, respeitando as respetivas licenças.

---

## 📁 Estrutura do projeto

```text
SafeGuit/
├── app.py
├── core.py
├── regras.yar
├── commit.ico
├── README.md
├── .gitignore
└── Projetos_Descarregados/
```

| Ficheiro ou pasta | Descrição |
| :--- | :--- |
| `app.py` | Interface gráfica Tkinter |
| `core.py` | Lógica de clonagem e análise |
| `regras.yar` | Regras de deteção YARA |
| `commit.ico` | Ícone da aplicação |
| `README.md` | Documentação do projeto |
| `.gitignore` | Ficheiros excluídos do Git |
| `Projetos_Descarregados/` | Repositórios descarregados para análise |

> ⚠️ A pasta `Projetos_Descarregados/` é criada durante a utilização e não deve ser publicada no repositório.

---

## 📦 Criar um executável Windows

### 1. Instalar o PyInstaller
Com o ambiente virtual ativado:
```bash
python -m pip install pyinstaller
```

### 2. Compilar a aplicação
Na pasta do projeto, executa:
```bash
python -m PyInstaller --clean --noconfirm --windowed --name GitGuard --collect-all yara --add-data "regras.yar;." --icon commit.ico app.py
```

Por predefinição, o PyInstaller cria uma pasta de distribuição. O executável deverá ficar em:
```text
dist/GitGuard/GitGuard.exe
```

Para gerar um único ficheiro executável, acrescenta `--onefile` ao comando. O resultado deverá ficar em:
```text
dist/GitGuard.exe
```

> ⚙️ **Importante:** antes de distribuir o executável, confirma que `core.py` resolve corretamente o caminho de `regras.yar` quando a aplicação está empacotada. Testa também a clonagem, a análise YARA e a disponibilidade do Git num computador Windows diferente.

---

## 🔐 Limitações e segurança

* O GitGuard não é um antivírus completo nem uma sandbox.
* A análise estática pode gerar falsos positivos e não identificar ameaças desconhecidas.
* O Microsoft Defender depende da disponibilidade e configuração do sistema.
* O VirusTotal pode não ter resultados para determinados hashes e está sujeito a limites de utilização.
* A eficácia do YARA depende das regras utilizadas.
* Não são instaladas automaticamente as dependências do repositório analisado.
* **Não executes código desconhecido apenas porque a análise terminou sem deteções.**
* Mantém as chaves API privadas e fora do controlo de versões.

---

## 👤 Autor

**Lord-beep**

---

## ⭐ Projeto

Se este projeto for útil, considera deixar uma estrela no repositório.
