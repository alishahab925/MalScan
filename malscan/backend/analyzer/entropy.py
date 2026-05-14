import math
import pefile
from typing import List, Dict, Any

def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte string."""
    if not data:
        return 0.0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_sections_entropy(file_path: str) -> List[Dict[str, Any]]:
    """
    Calculates Shannon entropy for each PE section.
    Flags any section with entropy above 7.0 as suspicious.
    """
    results = []
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            entropy = calculate_entropy(section.get_data())
            results.append({
                "section_name": section.Name.decode().strip('\x00'),
                "entropy": round(entropy, 4),
                "is_suspicious": entropy > 7.0
            })
        pe.close()
    except Exception as e:
        # If it's not a valid PE or other error, we might still want to calculate entropy of the whole file
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                entropy = calculate_entropy(data)
                results.append({
                    "section_name": "WHOLE_FILE",
                    "entropy": round(entropy, 4),
                    "is_suspicious": entropy > 7.0
                })
        except:
            pass

    return results
