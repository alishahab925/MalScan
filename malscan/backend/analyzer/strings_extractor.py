import re
from typing import List

def extract_strings(file_path: str) -> List[str]:
    """
    Extracts ASCII and Unicode strings from a binary file.
    Min length: 4. Returns deduplicated list sorted by length descending.
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except Exception:
        return []

    # ASCII strings
    ascii_re = re.compile(rb'[ -~]{4,}')
    ascii_strings = [s.decode('ascii') for s in ascii_re.findall(data)]

    # Unicode strings (UTF-16LE)
    unicode_re = re.compile(rb'(?:[\x20-\x7E][\x00]){4,}')
    unicode_strings = [s.decode('utf-16le') for s in unicode_re.findall(data)]

    # Combine, deduplicate and sort
    all_strings = list(set(ascii_strings + unicode_strings))
    all_strings.sort(key=len, reverse=True)

    return all_strings
