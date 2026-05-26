import os

def analyze_pe_file(file_path: str):
    if not os.path.exists(file_path):
        return {}
        
    try:
        # Only import pefile if we actually use it
        import pefile
    except ImportError:
        return {}
        
    try:
        pe = pefile.PE(file_path)
    except Exception:
        return {} # Not a valid PE file

    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', 'ignore') if entry.dll else "Unknown"
            for imp in entry.imports:
                func_name = imp.name.decode('utf-8', 'ignore') if imp.name else "Ordinal"
                imports.append(f"{dll_name}:{func_name}")

    sections = []
    suspicious_sections = False
    for section in pe.sections:
        name = section.Name.decode('utf-8', 'ignore').strip('\x00')
        entropy = section.get_entropy()
        sections.append({"name": name, "entropy": entropy})
        
        # UPX or highly packed sections usually have entropy > 7.0
        if entropy > 7.0 or name.upper() in ('UPX0', 'UPX1'):
            suspicious_sections = True

    suspicious_apis = [
        api for api in imports if any(
            susp_api in api.lower() for susp_api in (
                'virtualalloc', 'createremotethread', 'writeprocessmemory', 
                'loadlibrary', 'getprocaddress', 'setwindowshook', 'urlmon'
            )
        )
    ]

    return {
        "is_pe": True,
        "imports": imports,
        "suspicious_apis": suspicious_apis,
        "sections": sections,
        "is_packed": suspicious_sections
    }
