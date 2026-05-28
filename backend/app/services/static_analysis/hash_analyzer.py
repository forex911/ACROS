import hashlib
import math
import mimetypes
import os

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def analyze_hashes(file_path: str):
    if not os.path.exists(file_path):
        return {}
        
    with open(file_path, "rb") as f:
        data = f.read()
    
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    entropy = compute_entropy(data)
    size = len(data)
    mime = mimetypes.guess_type(file_path)[0] or "application/octet-stream"

    return {
        "sha256": sha256,
        "md5": md5,
        "entropy": entropy,
        "size": size,
        "mime": mime
    }
