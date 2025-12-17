"""
Secure Messaging Server - REST API (Modular Architecture)
Organized by functionality: Crypto, AI, API Routes, Main
"""

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json
import os
import requests
from datetime import datetime

# GLOBAL STATE

app = Flask(__name__)

# RSA Keys
rsa_private_key = None
rsa_public_key = None

# Session Management
session_keys = {}  # Store AES keys per client
message_history = []  # For logging and analysis


# CRYPTOGRAPHY MODULE - RSA Key Management

class RSAKeyManager:
    """Handles RSA key generation and operations"""

    @staticmethod
    def generate_key_pair():
        """Generate RSA-2048 public/private key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(public_key):
        """Convert public key to Base64 PEM format for transmission"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pem).decode('utf-8')

    @staticmethod
    def decrypt_aes_key(encrypted_key_b64, private_key):
        """Decrypt AES session key using RSA private key"""
        encrypted_key = base64.b64decode(encrypted_key_b64)
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key


# CRYPTOGRAPHY MODULE - AES Encryption/Decryption

class AESCipher:
    """Handles AES-256-CBC encryption and decryption"""

    @staticmethod
    def decrypt_message(encrypted_data_b64, aes_key, iv_b64):
        """
        Decrypt message using AES-256-CBC
        Returns: Decrypted plaintext string
        """
        # Decode from Base64
        encrypted_data = base64.b64decode(encrypted_data_b64)
        iv = base64.b64decode(iv_b64)

        # Create cipher and decrypt
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove PKCS7 padding
        padding_length = padded_data[-1]
        plaintext = padded_data[:-padding_length]

        return plaintext.decode('utf-8')

# CRYPTOGRAPHY MODULE - HMAC Integrity Validation

class HMACValidator:
    """Handles HMAC-SHA256 message authentication"""

    @staticmethod
    def verify_hmac(message, received_hmac_b64, aes_key):
        """
        Verify message integrity using HMAC-SHA256
        Returns: True if valid, False if tampered
        """
        try:
            # Decode received HMAC
            received_hmac = base64.b64decode(received_hmac_b64)

            # Compute expected HMAC
            h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
            h.update(message.encode('utf-8'))
            computed_hmac = h.finalize()

            # Constant-time comparison
            return computed_hmac == received_hmac

        except Exception as e:
            print(f"HMAC verification error: {e}")
            return False

# AI MODULE - Ollama Integration for Anomaly Detection

class OllamaAIDetector:
    """AI-powered threat detection using Ollama LLM"""

    OLLAMA_API_URL = 'http://localhost:11434/api/generate'
    MODEL_NAME = 'tinyllama'
    TIMEOUT = 30  # seconds

    @staticmethod
    def analyze_message(message_data):
        """
        Analyze message content using Ollama AI
        Returns: List of detected anomalies (empty if clean)
        """
        anomalies = []

        try:
            # Extract message details
            content = message_data.get('content', '')
            sender_info = message_data.get('sender', {})
            sender_name = sender_info.get('name', 'Unknown')
            sender_email = sender_info.get('email', 'unknown@unknown.com')

            # Construct security analysis prompt
            prompt = OllamaAIDetector._build_security_prompt(
                content, sender_name, sender_email
            )

            # Call Ollama API
            ai_response = OllamaAIDetector._call_ollama_api(prompt)

            if ai_response:
                # Parse and process AI analysis
                anomalies = OllamaAIDetector._process_ai_response(
                    ai_response, message_data
                )
            else:
                anomalies.append("AI analysis failed - service unavailable")

        except requests.exceptions.ConnectionError:
            anomalies.append(
                "AI service unavailable - Ollama not running on localhost:11434"
            )
            print("️  Warning: Cannot connect to Ollama. Is it running?")

        except requests.exceptions.Timeout:
            anomalies.append("AI analysis timed out")

        except Exception as e:
            anomalies.append(f"AI analysis error: {str(e)}")
            print(f" AI Detection Error: {e}")

        return anomalies

    @staticmethod
    def _build_security_prompt(content, sender_name, sender_email):
        """Construct the security analysis prompt for AI"""
        return f"""You are a security analyst examining a message for potential threats.

Message Content: "{content}"
Sender: {sender_name} ({sender_email})
Message Length: {len(content)} characters

Analyze this message and determine if it contains any of the following:
1. Malicious intent (hacking, exploitation, unauthorized access)
2. Injection attacks (SQL, code injection, XSS)
3. Spam or phishing attempts
4. Social engineering tactics
5. Inappropriate or threatening content
6. Data exfiltration attempts
7. Malware references or distribution

Respond in JSON format:
{{
  "is_suspicious": true or false,
  "threat_level": "none", "low", "medium", or "high",
  "detected_threats": ["list of specific threats found"],
  "explanation": "brief explanation of findings",
  "recommended_action": "allow", "flag", or "block"
}}

Be concise and focus only on security concerns. If the message is benign, set is_suspicious to false."""

    @staticmethod
    def _call_ollama_api(prompt):
        """Make API call to Ollama"""
        try:
            response = requests.post(
                OllamaAIDetector.OLLAMA_API_URL,
                json={
                    'model': OllamaAIDetector.MODEL_NAME,
                    'prompt': prompt,
                    'stream': False,
                    'format': 'json'
                },
                timeout=OllamaAIDetector.TIMEOUT
            )

            if response.status_code == 200:
                ollama_data = response.json()
                return ollama_data.get('response', '{}')
            else:
                print(f"Ollama API error: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"Ollama API call failed: {e}")
            return None

    @staticmethod
    def _process_ai_response(ai_response_text, message_data):
        """Parse and process AI response into anomaly list"""
        anomalies = []

        try:
            # Parse JSON response
            ai_analysis = json.loads(ai_response_text)

            # Store full analysis in message
            message_data['ai_analysis'] = ai_analysis

            # Check if suspicious
            if ai_analysis.get('is_suspicious', False):
                threat_level = ai_analysis.get('threat_level', 'unknown')
                threats = ai_analysis.get('detected_threats', [])
                explanation = ai_analysis.get('explanation', 'No explanation')
                action = ai_analysis.get('recommended_action', 'flag')

                # Format anomaly message
                anomaly_msg = f"AI Detection - Threat Level: {threat_level.upper()}"
                if threats:
                    anomaly_msg += f" | Threats: {', '.join(threats)}"
                anomaly_msg += f" | Action: {action.upper()}"
                anomaly_msg += f" | Details: {explanation}"

                anomalies.append(anomaly_msg)
            else:
                # Message is clean
                message_data['ai_analysis'] = {
                    'is_suspicious': False,
                    'threat_level': 'none',
                    'status': 'clean'
                }

        except json.JSONDecodeError:
            anomalies.append("AI analysis returned invalid JSON")
            print(f"Warning: Could not parse AI response: {ai_response_text[:100]}...")

        return anomalies

# MESSAGE PROCESSING MODULE

class MessageProcessor:
    """Handles the complete message processing pipeline"""

    @staticmethod
    def process_encrypted_message(data):
        """
        Complete pipeline: Decrypt → Verify → Analyze
        Returns: (success, result_dict)
        """
        try:
            # Step 1: Extract payload components
            encrypted_aes_key_b64 = data['encrypted_aes_key']
            encrypted_message_b64 = data['encrypted_message']
            iv_b64 = data['iv']
            hmac_b64 = data['hmac']
            client_id = data.get('client_id', 'unknown')

            print(f"\n[PROCESSING] Message from client: {client_id}")

            # Step 2: Decrypt AES session key using RSA
            print("  → Decrypting AES key with RSA...")
            aes_key = RSAKeyManager.decrypt_aes_key(
                encrypted_aes_key_b64,
                rsa_private_key
            )
            session_keys[client_id] = aes_key
            print("  AES key decrypted")

            # Step 3: Decrypt message using AES
            print("  Decrypting message with AES-256-CBC...")
            decrypted_message = AESCipher.decrypt_message(
                encrypted_message_b64,
                aes_key,
                iv_b64
            )
            print("  Message decrypted")

            # Step 4: Verify HMAC integrity
            print("  Verifying HMAC-SHA256...")
            if not HMACValidator.verify_hmac(decrypted_message, hmac_b64, aes_key):
                print("  HMAC verification FAILED!")
                return False, {
                    'status': 'error',
                    'message': 'HMAC verification failed - message may be tampered!'
                }
            print(" HMAC verified - message integrity confirmed")

            # Step 5: Deserialize JSON payload
            print(" Deserializing JSON payload...")
            message_data = json.loads(decrypted_message)
            print(" JSON deserialized")

            # Step 6: AI Anomaly Detection
            print("  → Running AI anomaly detection...")
            anomalies = OllamaAIDetector.analyze_message(message_data)

            if anomalies:
                print(f"{len(anomalies)} anomaly(ies) detected!")
                for anomaly in anomalies:
                    print(f"     - {anomaly}")
            else:
                print("  ✓ No anomalies detected - message is clean")

            # Step 7: Store in history
            message_data['timestamp'] = datetime.now().isoformat()
            message_data['anomalies'] = anomalies
            message_data['client_id'] = client_id
            message_history.append(message_data)

            # Step 8: Prepare response
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

            print(f"  ✓ Processing complete\n")
            return True, response

        except json.JSONDecodeError:
            return False, {
                'status': 'error',
                'message': 'Invalid JSON in message payload'
            }
        except KeyError as e:
            return False, {
                'status': 'error',
                'message': f'Missing required field: {str(e)}'
            }
        except Exception as e:
            return False, {
                'status': 'error',
                'message': f'Server error: {str(e)}'
            }

# REST API ROUTES

@app.route('/api/public-key', methods=['GET'])
def get_public_key():
    """
    Endpoint: GET /api/public-key
    Returns: RSA public key for clients to encrypt session keys
    """
    return jsonify({
        'status': 'success',
        'public_key': RSAKeyManager.serialize_public_key(rsa_public_key),
        'algorithm': 'RSA-2048',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/message', methods=['POST'])
def receive_message():
    """
    Endpoint: POST /api/message
    Receives encrypted message with HMAC
    Pipeline: RSA decrypt → AES decrypt → HMAC verify → AI analyze
    """
    data = request.json
    success, result = MessageProcessor.process_encrypted_message(data)

    if success:
        return jsonify(result), 200
    else:
        status_code = 401 if 'HMAC' in result.get('message', '') else 400
        return jsonify(result), status_code


@app.route('/api/messages/history', methods=['GET'])
def get_message_history():
    """
    Endpoint: GET /api/messages/history
    Returns: Last 10 received messages with analysis
    """
    return jsonify({
        'status': 'success',
        'message_count': len(message_history),
        'messages': message_history[-10:]
    })


@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Endpoint: GET /api/health
    Returns: Server status and statistics
    """
    return jsonify({
        'status': 'healthy',
        'active_sessions': len(session_keys),
        'messages_received': len(message_history),
        'timestamp': datetime.now().isoformat()
    })


# SERVER INITIALIZATION AND STARTUP

def initialize_server():
    """Initialize server components and generate keys"""
    global rsa_private_key, rsa_public_key

    print("=" * 60)
    print("SECURE MESSAGING SERVER - INITIALIZING")
    print("=" * 60)

    # Generate RSA keys
    print("\n[1] Generating RSA-2048 key pair...")
    rsa_private_key, rsa_public_key = RSAKeyManager.generate_key_pair()
    print("✓ RSA keys generated successfully")

    # Display configuration
    print("\n[2] Server Configuration:")
    print("    - Encryption: AES-256-CBC")
    print("    - Key Exchange: RSA-2048 with OAEP")
    print("    - Integrity: HMAC-SHA256")
    print("    - Protocol: REST API")
    print("    - AI Detection: Ollama LLM (llama3.2)")
    print("    - AI Endpoint: http://localhost:11434")

    # List available endpoints
    print("\n[3] Available Endpoints:")
    print("    GET  /api/public-key       - Get RSA public key")
    print("    POST /api/message          - Send encrypted message")
    print("    GET  /api/messages/history - View message history")
    print("    GET  /api/health           - Health check")

    # Startup information
    print("\n[4] Starting Flask server on http://localhost:5000")
    print("\n  IMPORTANT: Ensure Ollama is running for AI detection")
    print("    Install: https://ollama.ai")
    print("    Start: ollama serve")
    print("    Pull model: ollama pull llama3.2")
    print("=" * 60)
    print("\nServer is ready to accept secure connections!\n")

# MAIN ENTRY POINT
if __name__ == '__main__':
    initialize_server()
    app.run(host='0.0.0.0', port=5000, debug=False)