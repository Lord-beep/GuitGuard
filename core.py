import os
import sys
import subprocess

def scan_with_windows_defender(folder_path):
    """Executa o antivírus local na pasta descarregada."""
    if os.name == 'nt':
        defender_path = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
        if os.path.exists(defender_path):
            try:
                result = subprocess.run([defender_path, "-Scan", "-ScanType", "3", "-File", folder_path], 
                                        capture_output=True, text=True)
                if "found no threats" in result.stdout.lower() or result.returncode == 0:
                    return True, "✅ Windows Defender: Nenhum vírus detetado."
                else:
                    return False, "🚨 PERIGO: O Antivírus detetou algo suspeito!"
            except Exception as e:
                return True, f"⚠️ Não foi possível rodar o antivírus: {e}"
        else:
            return True, "⚠️ Windows Defender não encontrado no caminho padrão."
    return True, "ℹ️ Sistema não é Windows. Verifique manualmente."

def basic_code_safety_check(folder_path):
    """Procura por funções e padrões de código potencialmente perigosos."""
    suspicious_terms = ["eval(", "exec(", "base64.b64decode", "os.system("]
    found_suspicious = False
    details = []
    
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(('.py', '.js', '.rs', '.sh', '.bat')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for term in suspicious_terms:
                            if term in content:
                                details.append(f"⚠️ Termo '{term}' em: {file}")
                                found_suspicious = True
                except Exception:
                    pass
    if not found_suspicious:
        return True, "✅ Inspeção visual: Nenhum padrão suspeito encontrado."
    return False, "\n".join(details)
