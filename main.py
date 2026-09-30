from flask import Flask, request, jsonify
import hmac
import hashlib
import sqlite3
from datetime import datetime

app = Flask(__name__)

WEBHOOK_SECRET = "super_secret_key_123"
DB_NAME = "webhooks.db"

def init_db():
    """Create the webhooks table if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            signature TEXT NOT NULL,
            payload TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_webhook(signature: str, payload_str: str):
    """Save an authenticated webhook payload to SQLite."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO webhook_events (timestamp, signature, payload) VALUES (?, ?, ?)",
        (datetime.utcnow().isoformat(), signature, payload_str)
    )
    conn.commit()
    conn.close()

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not signature:
        return False
    if signature.startswith("sha256="):
        signature = signature[7:]
    expected_sig = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_sig, signature)

@app.route("/webhook", methods=["POST"])
def webhook():
    raw_body = request.get_data()
    signature = request.headers.get("X-Signature-256", "")
    
    if not verify_signature(raw_body, signature, WEBHOOK_SECRET):
        print("\n[SECURITY ALERT] Rejected unauthorized webhook!")
        return jsonify({"status": "error", "message": "Invalid signature"}), 401
        
    payload_str = raw_body.decode("utf-8")
    save_webhook(signature, payload_str)
    
    print("\n================ AUTHENTICATED & STORED ================")
    print(f"Stored Payload: {payload_str}")
    print("========================================================\n")
    
    return jsonify({"status": "success", "message": "Webhook authenticated and stored in SQLite"}), 200

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=8000, debug=True)
