from cryptography.fernet import Fernet
from config import Config

class SecureVault:
    def __init__(self):
        # Load the Master Key
        # In a real app, this should come from an environment variable, not code
        self.key = Config.ENCRYPTION_KEY
        if self.key == b'YourGeneratedKeyMustBe32UrlSafeBase64Bytes=':
             # Generates a temp key if you didn't set one (prevents crash)
             self.key = Fernet.generate_key() 
        self.cipher = Fernet(self.key)

    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypts raw bytes (file content) using AES-256"""
        return self.cipher.encrypt(data)

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypts bytes back to original content"""
        return self.cipher.decrypt(encrypted_data)

    def is_safe_file(self, filename):
        """Security: Validates file extension (Allow List)"""
        ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt'}
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS