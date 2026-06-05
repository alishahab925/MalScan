import os
import shutil
import uuid
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

from analyzer.pe_parser import parse_pe
from analyzer.entropy import analyze_sections_entropy
from analyzer.strings_extractor import extract_strings
from analyzer.ioc_extractor import extract_iocs
from analyzer.ai_interpreter import analyze_with_ai
from utils.file_validator import validate_file

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Rate limiter: 100 requests/hour per IP
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:path>')
def send_static(path):
    return send_from_directory('../frontend', path)

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"})

@app.route('/api/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Read file to get size for validation
    file_content = file.read()
    file_size = len(file_content)

    is_valid, error_msg = validate_file(file.filename, file_size)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    # Save file temporarily - sanitize filename to prevent path traversal
    safe_filename = secure_filename(file.filename)
    temp_filename = f"{uuid.uuid4()}_{safe_filename}"
    file_path = os.path.join(UPLOAD_FOLDER, temp_filename)

    try:
        with open(file_path, 'wb') as f:
            f.write(file_content)

        # Run Analysis
        # 1. PE Parsing
        pe_info = parse_pe(file_path)

        # 2. Entropy Analysis
        entropy_info = analyze_sections_entropy(file_path)

        # 3. String Extraction
        strings = extract_strings(file_path)

        # 4. IOC Extraction
        iocs = extract_iocs(strings)

        # Combine results for AI
        combined_data = {
            "pe_header": pe_info,
            "entropy": entropy_info,
            "iocs": iocs,
            "strings_count": len(strings),
            "top_strings": strings[:100] # Send top 100 strings to Claude
        }

        # 5. AI Interpretation
        ai_report = analyze_with_ai(combined_data)

        full_report = {
            "static_analysis": {
                "pe_info": pe_info,
                "entropy": entropy_info,
                "iocs": iocs
            },
            "ai_report": ai_report
        }

        return jsonify(full_report)

    except Exception as e:
        app.logger.error(f"Analysis failed: {str(e)}")
        return jsonify({"error": "Analysis failed due to an internal error."}), 500

    finally:
        # Delete file after analysis
        if os.path.exists(file_path):
            os.remove(file_path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
