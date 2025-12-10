"""
Secure Messaging Client - CLI Application
Implements student object serialization, RSA encryption, AES encryption, HMAC signing
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


# Student class for serialization
class Student:
    """Student object to be serialized and sent securely"""

    def __init__(self, student_id, name, email, major, gpa, courses):
        self.student_id = student_id
        self.name = name
        self.email = email
        self.major = major
        self.gpa = gpa
        self.courses = courses
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        """Serialize student object to dictionary"""
        return {
            'student_id': self.student_id,
            'name': self.name,
            'email': self.email,
            'major': self.major,
            'gpa': self.gpa,
            'courses': self.courses,
            'timestamp': self.timestamp
        }

    def __str__(self):
        return f"Student({self.name}, {self.email}, {self.major})"


class SecureMessagingClient:
    """Client for secure messaging with encryption and authentication"""

    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url
        self.rsa_public_key = None
        self.aes_key = None
        self.client_id = f"client_{os.urandom(4).hex()}"

    def fetch_public_key(self):
        """Fetch RSA public key from server"""
        try:
            print("\n[1] Fetching RSA public key from server...")
            response = requests.get(f'{self.server_url}/api/public-key')

            if response.status_code == 200:
                data = response.json()
                public_key_pem = base64.b64decode(data['public_key'])

                self.rsa_public_key = serialization.load_pem_public_key(
                    public_key_pem,
                    backend=default_backend()
                )
                print(f"✓ Public key received: {data['algorithm']}")
                return True
            else:
                print(f"✗ Failed to fetch public key: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print("✗ Cannot connect to server. Is it running?")
            return False
        except Exception as e:
            print(f"✗ Error: {e}")
            return False

    def generate_aes_key(self):
        """Generate AES-256 symmetric key for session"""
        self.aes_key = os.urandom(32)  # 256 bits
        print(f"✓ Generated AES-256 session key")

    def encrypt_aes_key(self):
        """Encrypt AES key using RSA public key"""
        encrypted_key = self.rsa_public_key.encrypt(
            self.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode('utf-8')

    def encrypt_message(self, message):
        """Encrypt message using AES-CBC"""
        # Generate random IV
        iv = os.urandom(16)

        # Add PKCS7 padding
        padding_length = 16 - (len(message) % 16)
        padded_message = message + chr(padding_length) * padding_length

        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_message.encode('utf-8')) + encryptor.finalize()

        return base64.b64encode(encrypted).decode('utf-8'), base64.b64encode(iv).decode('utf-8')

    def compute_hmac(self, message):
        """Compute HMAC-SHA256 for message integrity"""
        h = hmac.HMAC(self.aes_key, hashes.SHA256(), backend=default_backend())
        h.update(message.encode('utf-8'))
        return base64.b64encode(h.finalize()).decode('utf-8')

    def create_message_payload(self, student, message_content):
        """Create complete message payload with student data"""
        payload = {
            'type': 'student_message',
            'sender': student.to_dict(),
            'content': message_content,
            'client_timestamp': datetime.now().isoformat()
        }
        return json.dumps(payload)

    def send_message(self, student, message_content):
        """Send encrypted message to server"""
        try:
            # Step 1: Generate AES key for this session
            print("\n[2] Generating session encryption key...")
            self.generate_aes_key()

            # Step 2: Encrypt AES key with RSA
            print("[3] Encrypting session key with RSA...")
            encrypted_aes_key = self.encrypt_aes_key()
            print("✓ Session key encrypted")

            # Step 3: Create and serialize message payload
            print("[4] Serializing student object to JSON...")
            message_payload = self.create_message_payload(student, message_content)
            print(f"✓ Payload size: {len(message_payload)} bytes")

            # Step 4: Encrypt message with AES
            print("[5] Encrypting message with AES-256-CBC...")
            encrypted_message, iv = self.encrypt_message(message_payload)
            print("✓ Message encrypted")

            # Step 5: Compute HMAC for integrity
            print("[6] Computing HMAC-SHA256 for integrity...")
            message_hmac = self.compute_hmac(message_payload)
            print("✓ HMAC computed")

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
            response = requests.post(
                f'{self.server_url}/api/message',
                json=transmission_payload,
                headers={'Content-Type': 'application/json'}
            )

            # Step 8: Process response
            if response.status_code == 200:
                result = response.json()
                print("\n" + "=" * 60)
                print("✓ MESSAGE SENT SUCCESSFULLY")
                print("=" * 60)
                print(f"Status: {result['status']}")
                print(f"HMAC Valid: {result['hmac_valid']}")
                print(f"Server Timestamp: {result['server_timestamp']}")

                if result.get('anomalies_detected'):
                    print("\nANOMALIES DETECTED:")
                    for anomaly in result.get('anomaly_details', []):
                        print(f"    - {anomaly}")
                else:
                    print("\n✓ No anomalies detected")

                print("=" * 60)
                return True
            else:
                result = response.json()
                print(f"\n✗ Error: {result.get('message', 'Unknown error')}")
                return False

        except Exception as e:
            print(f"\n✗ Failed to send message: {e}")
            return False


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


def create_sample_student():
    """Create a sample student object"""
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


def main():
    """Main application loop"""
    print("\n" + "=" * 60)
    print("INITIALIZING SECURE MESSAGING CLIENT")
    print("=" * 60)

    client = SecureMessagingClient()

    # Fetch public key from server
    if not client.fetch_public_key():
        print("\nCannot proceed without server connection.")
        print("Please ensure the server is running on http://localhost:5000")
        return

    while True:
        display_menu()
        choice = input("\nSelect option (1-4): ").strip()

        if choice == '1':
            # Send secure message
            student = create_sample_student()
            print(f"\nStudent object created: {student}")

            message = input("\nEnter message to send: ").strip()
            if message:
                client.send_message(student, message)
            else:
                print("Message cannot be empty.")

        elif choice == '2':
            # View message history
            try:
                response = requests.get(f'{client.server_url}/api/messages/history')
                if response.status_code == 200:
                    data = response.json()
                    print(f"\n--- Message History ({data['message_count']} total) ---")
                    for idx, msg in enumerate(data['messages'], 1):
                        print(f"\n{idx}. From: {msg['sender']['name']} ({msg['sender']['email']})")
                        print(f"   Content: {msg['content']}")
                        print(f"   Timestamp: {msg['timestamp']}")
                        if msg.get('anomalies'):
                            print(f"Anomalies: {', '.join(msg['anomalies'])}")
            except Exception as e:
                print(f"Error fetching history: {e}")

        elif choice == '3':
            # Test anomaly detection
            print("\n--- Anomaly Detection Test ---")
            print("1. Send very long message (triggers length anomaly)")
            print("2. Send message with suspicious keywords")
            print("3. Send multiple rapid messages (rate limiting)")

            test_choice = input("Select test (1-3): ").strip()
            student = Student("TEST001", "Test User", "test@test.com", "Testing", 4.0, ["TEST101"])

            if test_choice == '1':
                client.send_message(student, "A" * 1500)  # Very long message
            elif test_choice == '2':
                client.send_message(student, "This message contains exploit and malware keywords")
            elif test_choice == '3':
                for i in range(6):
                    print(f"\nSending message {i + 1}/6...")
                    client.send_message(student, f"Rapid message {i + 1}")

        elif choice == '4':
            print("\nExiting... Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
    except Exception as e:
        print(f"\nUnexpected error: {e}")