import ast
import os

def analyze_python_file(file_path: str):
    if not os.path.exists(file_path) or not file_path.endswith('.py'):
        return {}
        
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception:
        return {}

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {}

    imports = []
    suspicious_calls = []
    uses_eval_exec = False
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                if func_name in ('eval', 'exec'):
                    uses_eval_exec = True
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    full_name = f"{node.func.value.id}.{node.func.attr}"
                    if full_name in (
                        'os.system', 'subprocess.Popen', 'subprocess.run', 'subprocess.call',
                        'socket.socket', 'requests.get', 'requests.post', 'urllib.request.urlopen'
                    ):
                        suspicious_calls.append(full_name)

    # Basic string search for indicators
    has_powershell = "powershell" in code.lower()
    has_base64 = "base64" in code.lower() or "b64decode" in code.lower()
    has_registry = "winreg" in code.lower() or "hkcu" in code.lower() or "hklm" in code.lower()

    findings = []
    
    if uses_eval_exec:
        findings.append({"type": "STATIC_FINDING", "rule": "EXEC_USAGE"})
    
    for call in suspicious_calls:
        if "os." in call or "subprocess." in call:
            findings.append({"type": "STATIC_FINDING", "rule": "SUBPROCESS_USAGE"})
        elif "socket." in call or "urllib." in call or "requests." in call:
            findings.append({"type": "STATIC_FINDING", "rule": "NETWORK_USAGE"})

    if has_powershell:
        findings.append({"type": "STATIC_FINDING", "rule": "POWERSHELL_USAGE"})
    if has_base64:
        findings.append({"type": "STATIC_FINDING", "rule": "BASE64_USAGE"})
    if has_registry:
        findings.append({"type": "STATIC_FINDING", "rule": "REGISTRY_USAGE"})

    return {
        "imports": list(set(imports)),
        "suspicious_calls": list(set(suspicious_calls)),
        "findings": findings
    }
