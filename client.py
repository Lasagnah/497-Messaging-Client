"""
Secure Messaging Client - CLI Application (Modular Architecture)
Organized by functionality: Student Model, Crypto, Network, UI, Main
"""

import requests
import base64
import json
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# DATA MODEL - Student Object for Serialization

class Student:
    """
    Student data model for serialization
    Represents the user sending messages
    """

    def __init__(self, student_id, name, email, major, gpa, courses):
        self.student_id = student_id
        self.name = name
        self.email = email
        self.major = major
        self.gpa = gpa
        self.courses = courses
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        """Serialize student object to dictionary for JSON encoding"""
        return {
            'student_id': self.student_id,
            'name': self.name,
            'email': self.email,
            'major': self.major,
            'gpa': self.gpa,
            'courses': self.courses,
            'timestamp': self.timestamp
        }

    def to_json(self):
        """Serialize student object directly to JSON string"""
        return json.dumps(self.to_dict())

    def __str__(self):
        return f"Student({self.name}, {self.email}, {self.major})"

# CRYPTOGRAPHY MODULE - RSA Operations

class RSAClient:
    """Handles RSA public key operations for key exchange"""

    def __init__(self):
        self.public_key = None

    def load_public_key(self, public_key_b64):
        """
        Load RSA public key from Base64 PEM format
        This key is received from the server
        """
        public_key_pem = base64.b64decode(public_key_b64)
        self.public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        return True

    def encrypt_aes_key(self, aes_key):
        """
        Encrypt AES session key with RSA public key
        Uses OAEP padding for security
        Returns: Base64 encoded encrypted key
        """
        encrypted_key = self.public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode('utf-8')

# CRYPTOGRAPHY MODULE - AES Operations

class AESClient:
    """Handles AES-256-CBC encryption operations"""

    def __init__(self):
        self.aes_key = None
        self.iv = None

    def generate_session_key(self):
        """Generate random AES-256 session key (32 bytes = 256 bits)"""
        self.aes_key = os.urandom(32)
        return self.aes_key

    def encrypt_message(self, plaintext):
        """
        Encrypt message using AES-256-CBC
        Returns: (encrypted_base64, iv_base64)
        """
        # Generate random IV for this message
        self.iv = os.urandom(16)

        # Add PKCS7 padding
        padding_length = 16 - (len(plaintext) % 16)
        padded_message = plaintext + chr(padding_length) * padding_length

        # Create cipher and encrypt
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CBC(self.iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_message.encode('utf-8'))
        encrypted += encryptor.finalize()

        # Return Base64 encoded values
        return (
            base64.b64encode(encrypted).decode('utf-8'),
            base64.b64encode(self.iv).decode('utf-8')
        )

    def get_key(self):
        """Get the current AES session key"""
        return self.aes_key

# CRYPTOGRAPHY MODULE - HMAC Operations

class HMACClient:
    """Handles HMAC-SHA256 message authentication"""

    @staticmethod
    def compute_hmac(message, aes_key):
        """
        Compute HMAC-SHA256 for message integrity
        Uses the same AES key for HMAC
        Returns: Base64 encoded HMAC
        """
        h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
        h.update(message.encode('utf-8'))
        hmac_bytes = h.finalize()
        return base64.b64encode(hmac_bytes).decode('utf-8')

# MESSAGE SERIALIZATION MODULE

class MessageSerializer:
    """Handles message payload creation and serialization"""

    @staticmethod
    def create_payload(student, message_content):
        """
        Create complete message payload with student data
        Returns: JSON string ready for encryption
        """
        payload = {
            'type': 'student_message',
            'sender': student.to_dict(),
            'content': message_content,
            'client_timestamp': datetime.now().isoformat()
        }
        return json.dumps(payload)


# NETWORK MODULE - Server Communication

class ServerAPI:
    """Handles all communication with the server"""

    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url

    def fetch_public_key(self):
        """
        Fetch RSA public key from server
        Returns: (success, public_key_b64 or error_message)
        """
        try:
            response = requests.get(f'{self.server_url}/api/public-key')

            if response.status_code == 200:
                data = response.json()
                return True, data['public_key']
            else:
                return False, f"HTTP {response.status_code}"

        except requests.exceptions.ConnectionError:
            return False, "Cannot connect to server"
        except Exception as e:
            return False, str(e)

    def send_encrypted_payload(self, payload):
        """
        Send encrypted payload to server
        Returns: (success, response_data)
        """
        try:
            response = requests.post(
                f'{self.server_url}/api/message',
                json=payload,
                headers={'Content-Type': 'application/json'}
            )

            return response.status_code == 200, response.json()

        except Exception as e:
            return False, {'error': str(e)}

    def get_message_history(self):
        """
        Fetch message history from server
        Returns: (success, history_data)
        """
        try:
            response = requests.get(f'{self.server_url}/api/messages/history')
            if response.status_code == 200:
                return True, response.json()
            return False, None
        except:
            return False, None

# MAIN CLIENT CLASS - Orchestrates All Operations

class SecureMessagingClient:
    """
    Main client class that orchestrates all security operations
    Combines: RSA, AES, HMAC, Serialization, Network
    """

    def __init__(self, server_url='http://localhost:5000'):
        self.server_api = ServerAPI(server_url)
        self.rsa_client = RSAClient()
        self.aes_client = AESClient()
        self.client_id = f"client_{os.urandom(4).hex()}"
        self.is_initialized = False

    def initialize(self):
        """
        Initialize client by fetching server's public key
        Must be called before sending messages
        """
        print("\n[1] Fetching RSA public key from server...")
        success, result = self.server_api.fetch_public_key()

        if success:
            self.rsa_client.load_public_key(result)
            self.is_initialized = True
            print("Public key received: RSA-2048")
            return True
        else:
            print(f"Failed to fetch public key: {result}")
            return False

    def send_secure_message(self, student, message_content):
        """
        Complete secure message sending pipeline:
        1. Generate AES key
        2. Encrypt AES key with RSA
        3. Serialize message
        4. Encrypt message with AES
        5. Compute HMAC
        6. Send to server
        """
        if not self.is_initialized:
            print("✗ Client not initialized. Call initialize() first.")
            return False

        try:
            # Step 1: Generate AES session key
            print("\n[2] Generating AES-256 session key...")
            self.aes_client.generate_session_key()
            print("Session key generated")

            # Step 2: Encrypt AES key with RSA
            print("[3] Encrypting session key with RSA...")
            encrypted_aes_key = self.rsa_client.encrypt_aes_key(
                self.aes_client.get_key()
            )
            print("Session key encrypted")

            # Step 3: Serialize message payload
            print("[4] Serializing student object to JSON...")
            message_payload = MessageSerializer.create_payload(
                student, message_content
            )
            print(f"Payload size: {len(message_payload)} bytes")

            # Step 4: Encrypt message with AES
            print("[5] Encrypting message with AES-256-CBC...")
            encrypted_message, iv = self.aes_client.encrypt_message(message_payload)
            print("Message encrypted")

            # Step 5: Compute HMAC for integrity
            print("[6] Computing HMAC-SHA256 for integrity...")
            message_hmac = HMACClient.compute_hmac(
                message_payload,
                self.aes_client.get_key()
            )
            print("HMAC computed")

            # Step 6: Prepare transmission payload
            transmission_payload = {
                'client_id': self.client_id,
                'encrypted_aes_key': encrypted_aes_key,
                'encrypted_message': encrypted_message,
                'iv': iv,
                'hmac': message_hmac
            }

            # Step 7: Send to server
            print("[7] Transmitting encrypted payload to server...")
            success, response = self.server_api.send_encrypted_payload(
                transmission_payload
            )

            # Step 8: Process response
            if success:
                self._display_success_response(response)
                return True
            else:
                print(f"\n✗ Error: {response.get('message', 'Unknown error')}")
                return False

        except Exception as e:
            print(f"\n✗ Failed to send message: {e}")
            return False

    def _display_success_response(self, response):
        """Display formatted success response"""
        print("\n" + "=" * 60)
        print("✓ MESSAGE SENT SUCCESSFULLY")
        print("=" * 60)
        print(f"Status: {response['status']}")
        print(f"HMAC Valid: {response['hmac_valid']}")
        print(f"Server Timestamp: {response['server_timestamp']}")

        if response.get('anomalies_detected'):
            print("\n⚠️  ANOMALIES DETECTED:")
            for anomaly in response.get('anomaly_details', []):
                print(f"    - {anomaly}")
        else:
            print("\n✓ No anomalies detected")

        print("=" * 60)

    def get_history(self):
        """Fetch and display message history"""
        success, data = self.server_api.get_message_history()
        return data if success else None

# USER INTERFACE MODULE

class UserInterface:
    """Handles all user interactions and display"""

    @staticmethod
    def display_menu():
        """Display main menu"""
        print("\n" + "=" * 60)
        print("SECURE MESSAGING CLIENT")
        print("=" * 60)
        print("1. Send a secure message")
        print("2. View server message history")
        print("3. Test anomaly detection")
        print("4. Exit")
        print("=" * 60)

    @staticmethod
    def get_student_info():
        """Get student information from user"""
        print("\n--- Student Information ---")
        name = input("Enter student name [John Doe]: ").strip() or "John Doe"
        email = input("Enter email [john.doe@university.edu]: ").strip() or "john.doe@university.edu"
        student_id = input("Enter student ID [S12345]: ").strip() or "S12345"
        major = input("Enter major [Computer Science]: ").strip() or "Computer Science"
        gpa = input("Enter GPA [3.75]: ").strip() or "3.75"
        courses = input("Enter courses (comma-separated) [CS101,CS202,MATH301]: ").strip() or "CS101,CS202,MATH301"

        return Student(
            student_id=student_id,
            name=name,
            email=email,
            major=major,
            gpa=float(gpa),
            courses=courses.split(',')
        )

    @staticmethod
    def display_history(history_data):
        """Display message history"""
        if not history_data:
            print("\n✗ Could not fetch history")
            return

        print(f"\n--- Message History ({history_data['message_count']} total) ---")
        for idx, msg in enumerate(history_data['messages'], 1):
            print(f"\n{idx}. From: {msg['sender']['name']} ({msg['sender']['email']})")
            print(f"   Content: {msg['content']}")
            print(f"   Timestamp: {msg['timestamp']}")
            if msg.get('anomalies'):
                print(f"    Anomalies: {', '.join(msg['anomalies'])}")

    @staticmethod
    def get_anomaly_test_choice():
        """Get anomaly test selection"""
        print("\n--- Anomaly Detection Test ---")
        print("1. SQL Injection attack")
        print("2. XSS (Cross-Site Scripting) attack")
        print("3. Phishing attempt")
        print("4. Clean message (control)")
        return input("Select test (1-4): ").strip()

# APPLICATION LOGIC

def run_send_message(client):
    """Handle sending a message"""
    student = UserInterface.get_student_info()
    print(f"\nStudent object created: {student}")

    message = input("\nEnter message to send: ").strip()
    if message:
        client.send_secure_message(student, message)
    else:
        print("Message cannot be empty.")


def run_view_history(client):
    """Handle viewing message history"""
    history = client.get_history()
    UserInterface.display_history(history)


def run_anomaly_test(client):
    """Handle anomaly detection testing"""
    choice = UserInterface.get_anomaly_test_choice()

    # Create test student
    student = Student(
        "TEST001", "Test User", "test@test.com",
        "Testing", 4.0, ["TEST101"]
    )

    test_messages = {
        '1': "'; DROP TABLE students; --",  # SQL Injection
        '2': "<script>alert('XSS')</script>",  # XSS
        '3': "URGENT: Click here to verify your account immediately!",  # Phishing
        '4': "Hello! How are you doing today?"  # Clean
    }

    message = test_messages.get(choice)
    if message:
        print(f"\nSending test message: {message}")
        client.send_secure_message(student, message)
    else:
        print("Invalid choice.")

# MAIN APPLICATION ENTRY POINT

def main():
    """Main application loop"""
    print("\n" + "=" * 60)
    print("INITIALIZING SECURE MESSAGING CLIENT")
    print("=" * 60)

    # Initialize client
    client = SecureMessagingClient()

    if not client.initialize():
        print("\nCannot proceed without server connection.")
        print("Please ensure the server is running on http://localhost:5000")
        return

    # Main loop
    while True:
        UserInterface.display_menu()
        choice = input("\nSelect option (1-4): ").strip()

        if choice == '1':
            run_send_message(client)

        elif choice == '2':
            run_view_history(client)

        elif choice == '3':
            run_anomaly_test(client)

        elif choice == '4':
            print("\nExiting... Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")

# PROGRAM START

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
    except Exception as e:
        print(f"\nUnexpected error: {e}")