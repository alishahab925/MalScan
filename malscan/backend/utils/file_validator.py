import os
from typing import Tuple

def validate_file(filename: str, file_size: int) -> Tuple[bool, str]:
    """
    Validates uploaded files.
    Allowed extensions: exe, dll, bin, sys.
    Max file size: 16MB.
    """
    allowed_extensions = os.getenv("ALLOWED_EXTENSIONS", "exe,dll,bin,sys").split(',')
    max_size_mb = int(os.getenv("MAX_FILE_SIZE_MB", 16))
    max_size_bytes = max_size_mb * 1024 * 1024

    if not filename:
        return False, "No filename provided."

    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    if ext not in allowed_extensions:
        return False, f"Invalid file extension. Allowed: {', '.join(allowed_extensions)}"

    if file_size > max_size_bytes:
        return False, f"File too large. Maximum size is {max_size_mb}MB."

    return True, ""
