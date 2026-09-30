import os
import sqlite3
import hmac
import hashlib
import json
from datetime import datetime
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.getenv("WEBHOOK_SECRET", "super_secret_key_123").encode("utf-8")
DB_NAME = "webhooks.db"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            payload TEXT NOT NULL,
            ai_analysis TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def analyze_payload_with_ai(payload_data):
    if not GEMINI_API_KEY:
        return "AI analysis skipped: GEMINI_API_KEY not configured."
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key={GEMINI_API_KEY}"
    
    prompt = f"""
    You are an automated security and data analyst monitoring incoming webhook payloads.
    Analyze the following JSON payload and provide a concise summary detailing:
    1. Core event type and intent.
    2. Any security anomalies or unusual fields.

    Payload:
    {json.dumps(payload_data, indent=2)}
    """
    
    headers = {"Content-Type": "application/json"}
    data = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            try:
                return result['candidates'][0]['content']['parts'][0]['text'].strip()
            except (KeyError, IndexError):
                return "AI analysis structure unexpected."
        else:
            return f"AI API Error Status {response.status_code}"
    except requests.exceptions.Timeout:
        # Graceful fallback for mobile network latency
        event_type = payload_data.get("event", "unknown_event")
        return f"Fallback Analysis: Received event type '{event_type}'. Payload processed successfully (AI timeout bypassed)."
    except Exception as e:
        return f"AI Analysis Failed: {str(e)}"

def verify_signature(payload_bytes, signature_header):
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    received_sig = signature_header.split("sha256=")[1]
    expected_sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(received_sig, expected_sig)

@app.route('/webhook', methods=['POST'])
def webhook_listener():
    signature = request.headers.get("X-Signature-256")
    raw_bytes = request.get_data()

    if not verify_signature(raw_bytes, signature):
        return jsonify({"error": "Invalid HMAC signature"}), 401

    try:
        payload = request.get_json()
    except Exception:
        return jsonify({"error": "Invalid JSON format"}), 400

    ai_summary = analyze_payload_with_ai(payload)

    timestamp = datetime.utcnow().isoformat()
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO webhook_events (timestamp, payload, ai_analysis) VALUES (?, ?, ?)",
            (timestamp, json.dumps(payload), ai_summary)
        )
        conn.commit()
        conn.close()
    except Exception as db_err:
        return jsonify({"error": f"Database error: {str(db_err)}"}), 500

    return jsonify({
        "status": "success",
        "message": "Webhook authenticated, analyzed, and stored in SQLite",
        "ai_analysis": ai_summary
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
