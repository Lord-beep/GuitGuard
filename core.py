from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# CONFIGURAÇÃO
# ============================================================

MAX_TEXT_SIZE = 2 * 1024 * 1024
MAX_FILE_SIZE = 650 * 1024 * 1024
MAX_REPO_FILES = 20_000
MAX_REPO_BYTES = 2 * 1024 * 1024 * 1024
MAX_VT_REQUESTS = 500
MAX_VT_RESPONSE = 2 * 1024 * 1024

CLONE_TIMEOUT = 180
DEFENDER_TIMEOUT = 900
VT_TIMEOUT = 20
YARA_TIMEOUT = 10

VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rs", ".go",
    ".java", ".c", ".h", ".cpp", ".cs", ".php", ".rb",
    ".sh", ".bash", ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".lua", ".pl", ".txt", ".json", ".yaml",
    ".yml", ".toml", ".ini", ".html", ".xml", ".md",
    ".gradle", ".properties", ".cfg", ".conf", ".sql",
    ".ipynb", ".dockerfile",
}

SUSPICIOUS_PATTERNS = [
    (
        "execução dinâmica",
        re.compile(r"\beval\s*\(|\bexec\s*\("),
    ),
    (
        "descodificação Base64",
        re.compile(r"\bbase64\.b64decode\s*\("),
    ),
    (
        "execução de comandos do sistema",
        re.compile(
            r"\bos\.system\s*\(|"
            r"\bsubprocess\.(?:Popen|run|call)\s*\("
        ),
    ),
    (
        "possível roubo de credenciais",
        re.compile(
            r"(?i)(steal.{0,30}password|grab.{0,30}token|"
            r"browser.{0,30}cookie|credential.{0,30}dump)"
        ),
    ),
    (
        "possível persistência no Windows",
        re.compile(
            r"(?i)CurrentVersion\\Run|schtasks\s+/create"
        ),
    ),
    (
        "possível desativação de proteções",
        re.compile(
            r"(?i)Set-MpPreference.{0,100}"
            r"DisableRealtimeMonitoring"
        ),
    ),
]

WEBHOOK_RE = re.compile(
    r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
    re.IGNORECASE,
)

IP_RE = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)


# ============================================================
# VALIDAÇÃO DE URL
# ============================================================

def validate_github_url(raw_url: str) -> tuple[str, str]:
    """Aceita URLs HTTPS simples de repositórios públicos GitHub."""
    if not isinstance(raw_url, str):
        raise ValueError("O URL tem de ser texto.")

    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Introduz um URL.")

    if any(ord(char) < 32 for char in raw_url):
        raise ValueError("O URL contém caracteres de controlo.")

    if "\\" in raw_url:
        raise ValueError("O URL contém barras inválidas.")

    try:
        parsed = urlparse(raw_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("O URL está malformado.") from exc

    if parsed.scheme.lower() != "https":
        raise ValueError("Só são aceites URLs HTTPS.")

    if parsed.hostname != "github.com":
        raise ValueError("Só são aceites URLs de github.com.")

    if parsed.username or parsed.password:
        raise ValueError("O URL não pode conter credenciais.")

    if port not in (None, 443):
        raise ValueError("Porta não permitida.")

    if parsed.query or parsed.fragment:
        raise ValueError(
            "O URL não pode conter parâmetros ou fragmentos."
        )

    parts = [part for part in parsed.path.split("/") if part]

    if len(parts) != 2:
        raise ValueError(
            "Formato esperado: "
            "https://github.com/UTILIZADOR/REPOSITORIO"
        )

    owner, repo = parts

    if repo.endswith(".git"):
        repo = repo[:-4]

    valid_name = re.compile(r"[A-Za-z0-9_.-]+")

    if not valid_name.fullmatch(owner):
        raise ValueError("Nome de utilizador inválido.")

    if not valid_name.fullmatch(repo):
        raise ValueError("Nome de repositório inválido.")

    if owner in {".", ".."} or repo in {".", ".."}:
        raise ValueError("Nome de repositório inválido.")

    return f"https://github.com/{owner}/{repo}.git", repo


# ============================================================
# INVENTÁRIO DE FICHEIROS
# ============================================================

def walk_files(folder_path):
    """Percorre ficheiros sem seguir ligações simbólicas."""
    base = Path(folder_path).resolve(strict=True)

    if not base.is_dir():
        raise ValueError("O destino não é um diretório.")

    for root, dirs, files in os.walk(base, followlinks=False):
        root_path = Path(root)

        dirs[:] = sorted(
            directory
            for directory in dirs
            if directory not in SKIP_DIRS
            and not (root_path / directory).is_symlink()
        )

        for name in sorted(files):
            path = root_path / name

            try:
                if path.is_symlink() or not path.is_file():
                    continue
                yield path
            except OSError:
                continue


def inventory_files(folder_path):
    """
    Devolve (ficheiros, erros).

    Limites excedidos ou erros de inventário significam
    que a análise não pode ser considerada completa.
    """
    files = []
    errors = []
    total_bytes = 0

    try:
        for path in walk_files(folder_path):
            try:
                size = path.stat().st_size
            except OSError:
                errors.append(
                    f"{path.name}: não foi possível obter o tamanho."
                )
                continue

            if len(files) >= MAX_REPO_FILES:
                errors.append(
                    f"Limite de {MAX_REPO_FILES} ficheiros excedido."
                )
                break

            if total_bytes + size > MAX_REPO_BYTES:
                errors.append(
                    "Limite de tamanho total do repositório excedido."
                )
                break

            files.append(path)
            total_bytes += size

    except (OSError, ValueError) as exc:
        errors.append(f"Inventário incompleto: {exc}")

    return files, errors


# ============================================================
# ANÁLISE ESTÁTICA
# ============================================================

def basic_code_safety_check(folder_path):
    """Análise heurística de texto; não é um antivírus."""
    findings = []
    errors = []
    checked = 0
    skipped_large = 0

    base = Path(folder_path).resolve()

    try:
        files, inventory_errors = inventory_files(base)
        errors.extend(inventory_errors)

        for path in files:
            if path.suffix.lower() not in TEXT_EXTENSIONS:
                continue

            try:
                if path.stat().st_size > MAX_TEXT_SIZE:
                    skipped_large += 1
                    continue

                content = path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                checked += 1
                relative = str(path.relative_to(base))

                for label, pattern in SUSPICIOUS_PATTERNS:
                    if pattern.search(content):
                        findings.append(
                            f"[SUSPEITO] {relative}: {label}"
                        )

                if WEBHOOK_RE.search(content):
                    findings.append(
                        f"[SEGREDO] {relative}: possível webhook exposto"
                    )

                for candidate in IP_RE.findall(content):
                    try:
                        address = ipaddress.ip_address(candidate)
                    except ValueError:
                        continue

                    if address.is_global:
                        findings.append(
                            f"[REVER] {relative}: IP público {candidate}"
                        )

            except OSError:
                errors.append(
                    f"Não foi possível ler o ficheiro {path.name}."
                )

    except (OSError, ValueError) as exc:
        return "unknown", f"Análise incompleta: {exc}"

    summary = (
        f"Análise estática: {checked} ficheiros de texto analisados."
    )

    if skipped_large:
        summary += (
            f" {skipped_large} ficheiro(s) excederam o limite de tamanho."
        )

    if findings:
        return "suspicious", summary + "\n" + "\n".join(findings)

    if errors or skipped_large:
        details = errors[:30]
        return (
            "unknown",
            summary + "\n" + "\n".join(details)
            + "\nAnálise incompleta; não considerar seguro.",
        )

    return (
        "clean",
        summary + "\nNenhum padrão configurado foi encontrado.",
    )


# ============================================================
# WINDOWS DEFENDER
# ============================================================

def _find_defender():
    """Localiza o executável do Microsoft Defender."""
    if os.name != "nt":
        return None

    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Windows Defender"
        / "MpCmdRun.exe",
    ]

    platform_dir = (
        Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        / "Microsoft"
        / "Windows Defender"
        / "Platform"
    )

    if platform_dir.is_dir():
        candidates.extend(
            sorted(
                platform_dir.glob("*/MpCmdRun.exe"),
                reverse=True,
            )
        )

    return next(
        (path for path in candidates if path.is_file()),
        None,
    )


def scan_with_windows_defender(folder_path):
    """Executa uma análise personalizada do Defender."""
    if os.name != "nt":
        return "unknown", "Windows Defender indisponível neste sistema."

    defender = _find_defender()

    if defender is None:
        return "unknown", "MpCmdRun.exe não foi encontrado."

    try:
        result = subprocess.run(
            [
                str(defender),
                "-Scan",
                "-ScanType", "3",
                "-File", str(Path(folder_path).resolve()),
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=DEFENDER_TIMEOUT,
            check=False,
            shell=False,
        )

        output = (
            result.stdout + "\n" + result.stderr
        ).strip()

        if result.returncode != 0:
            return (
                "unknown",
                f"Defender terminou com código {result.returncode}.\n"
                f"{output[-2000:]}",
            )

        lower = output.casefold()

        threat_markers = (
            "threat detected",
            "threats detected",
            "threat found",
            "threats found",
            "ameaça detetada",
            "ameaças detetadas",
        )

        clean_markers = (
            "no threats found",
            "no threats detected",
            "found no threats",
            "nenhuma ameaça encontrada",
            "nenhuma ameaça detetada",
        )

        if any(marker in lower for marker in threat_markers):
            return (
                "threat",
                "Defender reportou uma ameaça.\n" + output[-2000:],
            )

        if any(marker in lower for marker in clean_markers):
            return (
                "clean",
                "Defender não reportou ameaças.\n" + output[-2000:],
            )

        return (
            "unknown",
            "Resultado do Defender não confirmado.\n"
            + output[-2000:],
        )

    except subprocess.TimeoutExpired:
        return "unknown", "A análise do Defender excedeu 15 minutos."

    except OSError as exc:
        return "unknown", f"Não foi possível executar o Defender: {exc}"

# ============================================================
# VIRUSTOTAL V3
# ============================================================

def scan_with_virustotal(
    folder_path,
    api_key=None,
    cancel_event=None,
):
    """
    Consulta hashes SHA-256 na API VirusTotal v3.
    Não envia automaticamente o conteúdo dos ficheiros.
    """
    if not api_key:
        return (
            "unknown",
            "VirusTotal ignorado: não foi fornecida uma API key.",
        )

    files, inventory_errors = inventory_files(folder_path)

    detections = []
    unknown = list(inventory_errors)
    checked = 0
    requests_made = 0

    for path in files:
        if cancel_event and cancel_event.is_set():
            unknown.append("Consulta cancelada.")
            break

        if requests_made >= MAX_VT_REQUESTS:
            unknown.append(
                f"Limite de {MAX_VT_REQUESTS} consultas atingido."
            )
            break

        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                unknown.append(
                    f"{path.name}: ficheiro demasiado grande."
                )
                continue

            digest = hashlib.sha256()

            with path.open("rb") as handle:
                for block in iter(
                    lambda: handle.read(1024 * 1024),
                    b"",
                ):
                    if cancel_event and cancel_event.is_set():
                        unknown.append("Cálculo do hash cancelado.")
                        break

                    digest.update(block)

            if cancel_event and cancel_event.is_set():
                break

            sha256 = digest.hexdigest()
            url = VT_BASE_URL + urllib.parse.quote(
                sha256,
                safe="",
            )

            request = urllib.request.Request(
                url,
                headers={
                    "x-apikey": api_key,
                    "Accept": "application/json",
                    "User-Agent": "GitGuard/2.0",
                },
            )

            requests_made += 1

            try:
                with urllib.request.urlopen(
                    request,
                    timeout=VT_TIMEOUT,
                ) as response:
                    raw = response.read(MAX_VT_RESPONSE + 1)

                if len(raw) > MAX_VT_RESPONSE:
                    unknown.append(
                        f"{path.name}: resposta demasiado grande."
                    )
                    continue

                data = json.loads(raw.decode("utf-8"))
                attributes = (
                    data.get("data", {}).get("attributes", {})
                )
                stats = attributes.get("last_analysis_stats")

                if not isinstance(stats, dict):
                    unknown.append(
                        f"{path.name}: estatísticas indisponíveis."
                    )
                    continue

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                checked += 1

                if malicious > 0 or suspicious > 0:
                    detections.append(
                        f"{path.name}: "
                        f"maliciosos={malicious}, "
                        f"suspeitos={suspicious}"
                    )

            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    unknown.append(
                        f"{path.name}: hash não encontrado."
                    )
                elif exc.code == 429:
                    unknown.append(
                        "Limite de pedidos do VirusTotal atingido."
                    )
                    break
                elif exc.code in (401, 403):
                    unknown.append(
                        "VirusTotal recusou a chave API ou o acesso."
                    )
                    break
                else:
                    unknown.append(
                        f"{path.name}: erro HTTP {exc.code}."
                    )

            except (
                urllib.error.URLError,
                TimeoutError,
                OSError,
                ValueError,
            ):
                unknown.append(
                    f"{path.name}: erro durante a consulta."
                )

        except OSError:
            unknown.append(
                f"{path.name}: erro ao calcular o hash."
            )

    summary = (
        f"VirusTotal: {checked} hashes com estatísticas disponíveis; "
        f"{len(detections)} ficheiros com deteções."
    )

    if detections:
        return (
            "threat",
            summary + "\n" + "\n".join(detections[:200]),
        )

    if unknown or checked != len(files):
        details = "\n".join(unknown[:30])

        return (
            "unknown",
            summary + "\nConsulta incompleta:\n" + details,
        )

    return (
        "clean",
        summary + "\nSem deteções nos resultados consultados.",
    )


# ============================================================
# YARA
# ============================================================

def scan_with_yara(folder_path, rules_path="regras.yar"):
    """
    Aplica regras YARA aos ficheiros do repositório.

    A ausência de regras ou falhas de análise não são
    consideradas resultados limpos.
    """
    try:
        import yara
    except ImportError:
        return (
            "unknown",
            "YARA não instalado; análise não realizada.",
        )

    rules_file = Path(rules_path)

    if not rules_file.is_file():
        return (
            "unknown",
            f"Ficheiro de regras YARA não encontrado: {rules_file}",
        )

    try:
        rules = yara.compile(filepath=str(rules_file))
    except Exception as exc:
        return (
            "unknown",
            f"Não foi possível compilar as regras YARA: {exc}",
        )

    files, errors = inventory_files(folder_path)
    findings = []
    checked = 0

    for path in files:
        try:
            matches = rules.match(
                filepath=str(path),
                timeout=YARA_TIMEOUT,
            )

            checked += 1

            for match in matches:
                findings.append(
                    f"{path.name}: regra YARA '{match.rule}'"
                )

        except Exception:
            errors.append(
                f"{path.name}: erro ou timeout na análise YARA."
            )

    summary = f"YARA: {checked}/{len(files)} ficheiros analisados."

    if findings:
        return (
            "threat",
            summary + "\n" + "\n".join(findings[:200]),
        )

    if errors or checked != len(files):
        return (
            "unknown",
            summary + "\n" + "\n".join(errors[:30]),
        )

    return (
        "clean",
        summary + " Sem correspondências.",
    )


# ============================================================
# CLONAGEM CONTROLADA DE REPOSITÓRIOS
# ============================================================

def clone_repository(
    repo_url,
    target,
    timeout=CLONE_TIMEOUT,
    cancel_event=None,
):
    """
    Clona um repositório GitHub público para uma pasta temporária
    e só depois transfere o repositório para o destino final.

    Não inicializa submódulos nem executa scripts do repositório.
    """
    repo_url, repo_name = validate_github_url(repo_url)

    base = (
        Path.cwd() / "Projetos_Descarregados"
    ).resolve()

    base.mkdir(parents=True, exist_ok=True)

    if base.is_symlink():
        raise ValueError(
            "A pasta de projetos não pode ser uma ligação simbólica."
        )

    target = Path(target)

    if target.exists() or target.is_symlink():
        raise ValueError("O destino já existe.")

    if target.name != repo_name:
        raise ValueError(
            "O nome do destino não corresponde ao repositório."
        )

    final_target = base / repo_name

    if final_target.exists() or final_target.is_symlink():
        raise FileExistsError("O destino já existe.")

    git_executable = shutil.which("git")

    if not git_executable:
        raise RuntimeError(
            "O executável Git não foi encontrado no PATH."
        )

    env = os.environ.copy()
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ALLOW_PROTOCOL": "https",
    })

    staging = Path(
        tempfile.mkdtemp(
            prefix=".gitguard-",
            dir=base,
        )
    )

    staged_repo = staging / repo_name

    command = [
        git_executable,
        "-c", "protocol.file.allow=never",
        "-c", "protocol.ext.allow=never",
        "clone",
        "--depth", "1",
        "--single-branch",
        "--no-recurse-submodules",
        "--",
        repo_url,
        str(staged_repo),
    ]

    process = None

    try:
        if cancel_event and cancel_event.is_set():
            raise InterruptedError("Clonagem cancelada.")

        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=env,
            shell=False,
        )

        deadline = time.monotonic() + timeout

        while True:
            if cancel_event and cancel_event.is_set():
                process.kill()
                process.communicate()
                raise InterruptedError("Clonagem cancelada.")

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                process.kill()
                process.communicate()
                raise TimeoutError(
                    "A clonagem excedeu o tempo limite."
                )

            try:
                output, _ = process.communicate(
                    timeout=min(0.25, remaining)
                )
                break
            except subprocess.TimeoutExpired:
                continue

        if process.returncode != 0:
            raise RuntimeError(
                "A clonagem falhou:\n"
                + (output or "")[-3000:]
            )

        if cancel_event and cancel_event.is_set():
            raise InterruptedError("Clonagem cancelada.")

        if final_target.exists() or final_target.is_symlink():
            raise FileExistsError(
                "O destino foi criado durante a clonagem."
            )

        # O staging e o destino final estão no mesmo diretório-base.
        # Não apagar nem substituir destinos preexistentes.
        os.rename(staged_repo, final_target)

        return final_target

    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()

        shutil.rmtree(staging, ignore_errors=True)