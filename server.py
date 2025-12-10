"""
Secure Messaging Server - REST API
Implements RSA key exchange, AES encryption, HMAC validation, and AI anomaly detection
"""

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json
import os
from datetime import datetime

app = Flask(__name__)

# Global storage
rsa_private_key = None
rsa_public_key = None
session_keys = {}  # Store AES keys per client
message_history = []  # For anomaly detection


def generate_rsa_keys():
    """Generate RSA public/private key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """Serialize public key to PEM format for transmission"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(pem).decode('utf-8')


def decrypt_aes_key(encrypted_key_b64):
    """Decrypt AES key using RSA private key"""
    encrypted_key = base64.b64decode(encrypted_key_b64)
    aes_key = rsa_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def decrypt_message(encrypted_data_b64, aes_key, iv_b64):
    """Decrypt message using AES"""
    encrypted_data = base64.b64decode(encrypted_data_b64)
    iv = base64.b64decode(iv_b64)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove PKCS7 padding
    padding_length = padded_data[-1]
    return padded_data[:-padding_length].decode('utf-8')


def verify_hmac(message, received_hmac_b64, aes_key):
    """Verify HMAC for message integrity"""
    received_hmac = base64.b64decode(received_hmac_b64)
    h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode('utf-8'))

    try:
        # Compare HMACs
        computed_hmac = h.finalize()
        return computed_hmac == received_hmac
    except:
        return False


def ai_anomaly_detection(message_data):
    """
    Simple AI-based anomaly detection
    Checks for: unusual message length, suspicious patterns, frequency
    """
    anomalies = []

    # Check message length
    msg_length = len(message_data.get('content', ''))
    if msg_length > 1000:
        anomalies.append(f"Unusually long message: {msg_length} chars")

    # Check for suspicious keywords
    suspicious_words = ['exploit', 'hack', 'malware', 'injection', 'DROP TABLE']
    content = message_data.get('content', '').lower()
    found_suspicious = [word for word in suspicious_words if word.lower() in content]
    if found_suspicious:
        anomalies.append(f"Suspicious keywords detected: {found_suspicious}")

    # Check message frequency (simple rate limiting)
    sender = message_data.get('sender', {}).get('email', 'unknown')
    recent_messages = [m for m in message_history[-10:]
                       if m.get('sender', {}).get('email') == sender]
    if len(recent_messages) >= 5:
        anomalies.append(f"High message frequency from {sender}")

    # Check for repeated content (spam detection)
    if len(message_history) > 0:
        last_content = message_history[-1].get('content', '')
        if content == last_content.lower():
            anomalies.append("Duplicate message detected (possible spam)")

    return anomalies


@app.route('/api/public-key', methods=['GET'])
def get_public_key():
    """Share RSA public key with clients"""
    return jsonify({
        'status': 'success',
        'public_key': serialize_public_key(rsa_public_key),
        'algorithm': 'RSA-2048',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/message', methods=['POST'])
def receive_message():
    """
    Receive encrypted message with HMAC
    Process: Decrypt AES key -> Verify HMAC -> Decrypt message -> AI check
    """
    try:
        data = request.json

        # Extract components
        encrypted_aes_key_b64 = data['encrypted_aes_key']
        encrypted_message_b64 = data['encrypted_message']
        iv_b64 = data['iv']
        hmac_b64 = data['hmac']
        client_id = data.get('client_id', 'unknown')

        # Step 1: Decrypt the AES session key using RSA
        aes_key = decrypt_aes_key(encrypted_aes_key_b64)
        session_keys[client_id] = aes_key

        # Step 2: Decrypt the message using AES
        decrypted_message = decrypt_message(encrypted_message_b64, aes_key, iv_b64)

        # Step 3: Verify HMAC for integrity
        if not verify_hmac(decrypted_message, hmac_b64, aes_key):
            return jsonify({
                'status': 'error',
                'message': 'HMAC verification failed - message may be tampered!'
            }), 401

        # Step 4: Parse the message (deserialize JSON)
        message_data = json.loads(decrypted_message)

        # Step 5: AI Anomaly Detection
        anomalies = ai_anomaly_detection(message_data)

        # Store in history
        message_data['timestamp'] = datetime.now().isoformat()
        message_data['anomalies'] = anomalies
        message_history.append(message_data)

        # Prepare response
        response = {
            'status': 'success',
            'message': 'Message received and verified',
            'decrypted_content': message_data,
            'hmac_valid': True,
            'anomalies_detected': len(anomalies) > 0,
            'anomaly_details': anomalies if anomalies else None,
            'server_timestamp': datetime.now().isoformat()
        }

        if anomalies:
            response['warning'] = 'Anomalies detected in message'

        return jsonify(response), 200

    except json.JSONDecodeError:
        return jsonify({
            'status': 'error',
            'message': 'Invalid JSON in message payload'
        }), 400
    except KeyError as e:
        return jsonify({
            'status': 'error',
            'message': f'Missing required field: {str(e)}'
        }), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Server error: {str(e)}'
        }), 500


@app.route('/api/messages/history', methods=['GET'])
def get_message_history():
    """Retrieve message history (last 10 messages)"""
    return jsonify({
        'status': 'success',
        'message_count': len(message_history),
        'messages': message_history[-10:]
    })


@app.route('/api/health', methods=['GET'])
def health_check():
    """Server health check"""
    return jsonify({
        'status': 'healthy',
        'active_sessions': len(session_keys),
        'messages_received': len(message_history),
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    print("=" * 60)
    print("SECURE MESSAGING SERVER - STARTING")
    print("=" * 60)

    # Generate RSA keys on startup
    print("\n[1] Generating RSA-2048 key pair...")
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    print("✓ RSA keys generated successfully")

    print("\n[2] Server Configuration:")
    print("    - Encryption: AES-256-CBC")
    print("    - Key Exchange: RSA-2048 with OAEP")
    print("    - Integrity: HMAC-SHA256")
    print("    - Protocol: REST API")
    print("    - AI Anomaly Detection: ENABLED")

    print("\n[3] Available Endpoints:")
    print("    GET  /api/public-key      - Get RSA public key")
    print("    POST /api/message         - Send encrypted message")
    print("    GET  /api/messages/history - View message history")
    print("    GET  /api/health          - Health check")

    print("\n[4] Starting Flask server on http://localhost:5000")
    print("=" * 60)
    print("\nServer is ready to accept secure connections!\n")

    app.run(host='0.0.0.0', port=5000, debug=False)