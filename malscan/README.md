# MalScan — AI-Powered Static Malware Analyzer

MalScan is a professional static malware analysis tool that leverages traditional heuristic analysis combined with AI-powered threat intelligence to provide comprehensive reports on suspicious Windows PE files.

## Features

- **PE Header Parsing**: Extracts compile time, architecture, sections, imports, and exports.
- **Entropy Analysis**: Calculates Shannon entropy per section to detect packing or encryption.
- **String Extraction**: Retrieves ASCII and Unicode strings from the binary.
- **IOC Detection**: Uses regex to find IPs, domains, URLs, registry keys, and suspicious API calls.
- **AI-Powered Reporting**: Utilizes Claude 3.5 Sonnet to interpret analysis results and generate professional threat reports.
- **MITRE ATT&CK Mapping**: Maps findings to relevant MITRE techniques.
- **Modern Web UI**: Clean, responsive dashboard for analysis and reporting.

## Sample Analysis Results

When a file is scanned, MalScan generates a detailed report. Here is an example of the AI-generated behavioral summary and MITRE mapping:

```json
{
  "threat_classification": "MALICIOUS",
  "confidence_score": 95,
  "threat_family": "Emotet",
  "behavioral_summary": "The file exhibits classic dropper behavior, attempting to establish persistence via registry keys and communicating with known C2 infrastructure.",
  "mitre_attack_techniques": [
    {
      "id": "T1059.003",
      "name": "Windows Command Shell",
      "description": "Adversaries may abuse the Windows command shell for execution."
    }
  ],
  "suspicious_indicators": [
    "High entropy in .text section (7.8)",
    "Call to VirtualAlloc followed by CreateRemoteThread",
    "Encoded PowerShell strings detected"
  ]
}
```

## How It Works

MalScan performs purely static analysis, meaning **files are never executed**.

1.  **PE Parser**: Uses `pefile` to disassemble the structure of Windows executables.
2.  **Entropy Calculator**: Identifies high-entropy sections (>7.0) which often indicate compressed or encrypted malicious payloads.
3.  **Strings & IOCs**: Scans the binary for human-readable patterns and known indicators of compromise.
4.  **AI Interpreter**: Sends the structured data to Claude for behavioral analysis and risk assessment.

## Quick Start with Docker

1.  Clone the repository.
2.  Create a `.env` file from `.env.example` and add your `ANTHROPIC_API_KEY`.
3.  Run the application:
    ```bash
    docker-compose up --build
    ```
4.  Access the UI at `http://localhost:5000`.

## Manual Setup

1.  **Backend**:
    ```bash
    cd malscan/backend
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python app.py
    ```
2.  **Frontend**:
    The backend serves the frontend (or you can open `frontend/index.html` directly if the API is running).

## Disclaimer

This tool is for **educational and defensive security research only**. Always handle malware samples with extreme caution in a controlled, isolated environment.

---
Built with Python, Flask, and Anthropic Claude.
