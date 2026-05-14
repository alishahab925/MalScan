import pefile
import datetime
from typing import Dict, Any, List

def parse_pe(file_path: str) -> Dict[str, Any]:
    """
    Parses a Windows PE file and extracts key information.

    Args:
        file_path: Path to the PE file.

    Returns:
        A dictionary containing extracted PE information.
    """
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {"error": f"Failed to parse PE: {str(e)}"}

    # Architecture
    arch = "64-bit" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else "32-bit"

    # Compile Timestamp
    timestamp = pe.FILE_HEADER.TimeDateStamp
    date = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat()

    # Sections
    sections = []
    for section in pe.sections:
        sections.append({
            "name": section.Name.decode().strip('\x00'),
            "raw_size": section.SizeOfRawData,
            "virtual_size": section.Misc_VirtualSize
        })

    # Import Table
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            imports[dll_name] = []
            for imp in entry.imports:
                imports[dll_name].append(imp.name.decode() if imp.name else f"ordinal_{imp.ordinal}")

    # Export Table
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(exp.name.decode() if exp.name else f"ordinal_{exp.ordinal}")

    # Packing Detection (Simple check)
    is_packed = False
    packed_indicators = ["UPX0", "UPX1", "UPX2", "ASPACK", "PECompact"]
    for section in sections:
        if any(ind in section["name"] for ind in packed_indicators):
            is_packed = True
            break

    if len(sections) < 3 and not is_packed:
        # Some heuristics
        is_packed = True # Very few sections often indicate packing

    result = {
        "architecture": arch,
        "compile_timestamp": date,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "is_packed": is_packed
    }

    pe.close()
    return result
