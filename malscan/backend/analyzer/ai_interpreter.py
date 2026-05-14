import anthropic
import json
import os
from typing import Dict, Any

def analyze_with_ai(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Uses Anthropic Claude to interpret the static analysis results.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return {"error": "Anthropic API key not configured."}

    client = anthropic.Anthropic(api_key=api_key)

    system_prompt = "You are a senior malware analyst at a threat intelligence firm. You will be given static analysis results from a suspicious file. Your job is to produce a professional threat report. Always respond with valid JSON only, no markdown, no explanation outside the JSON."

    user_prompt = f"Analyze these static analysis results and return a JSON object with exactly these fields: threat_classification (string), confidence_score (integer 0-100), threat_family (string or null), behavioral_summary (string), mitre_attack_techniques (array of objects with id, name, description), suspicious_indicators (array of strings ranked by severity), recommended_actions (array of strings), analyst_notes (string). Here is the data: {json.dumps(analysis_data)}"

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt}
            ]
        )

        # Extract content from Claude's response
        response_text = message.content[0].text

        # Safely parse JSON
        return json.loads(response_text)
    except Exception as e:
        return {"error": f"AI analysis failed: {str(e)}"}
