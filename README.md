"""
DNS Record Digital Signature Module
Implements RSA-2048 signing and verification for DNS records
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import json
import base64
from typing import Dict, Tuple, Optional

class DNSRecordSigner:
    """Handles digital signatures for DNS records using RSA"""
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize the signer
        
        Args:
            key_size: RSA key size (default: 2048)
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self) -> Tuple:
        """
        Generate RSA key pair
        
        Returns:
            Tuple of (private_key, public_key)
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def sign_record(self, record: Dict) -> Dict:
        """
        Sign a DNS record
        
        Args:
            record: Dictionary containing DNS record data
            
        Returns:
            Dictionary with record, signature, and public key
        """
        if not self.private_key:
            self.generate_keys()
        
        # Serialize record to bytes
        record_bytes = json.dumps(record, sort_keys=True).encode()
        
        # Sign the record
        signature = self.private_key.sign(
            record_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return {
            'record': record,
            'signature': base64.b64encode(signature).decode(),
            'public_key': self.export_public_key()
        }
    
    def verify_signature(self, signed_record: Dict) -> bool:
        """
        Verify DNS record signature
        
        Args:
            signed_record: Dictionary containing record, signature, and public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Serialize record to bytes
            record_bytes = json.dumps(
                signed_record['record'], 
                sort_keys=True
            ).encode()
            
            # Decode signature
            signature = base64.b64decode(signed_record['signature'])
            
            # Load public key
            public_key = serialization.load_pem_public_key(
                signed_record['public_key'].encode(),
                backend=default_backend()
            )
            
            # Verify signature
            public_key.verify(
                signature,
                record_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
            
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Verification error: {e}")
            return False
    
    def export_public_key(self) -> str:
        """
        Export public key in PEM format
        
        Returns:
            PEM-encoded public key string
        """
        if not self.public_key:
            raise ValueError("No public key available")
            
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode()
    
    def export_private_key(self, password: Optional[bytes] = None) -> str:
        """
        Export private key in PEM format
        
        Args:
            password: Optional password for encryption
            
        Returns:
            PEM-encoded private key string
        """
        if not self.private_key:
            raise ValueError("No private key available")
        
        encryption = serialization.BestAvailableEncryption(password) if password \
                     else serialization.NoEncryption()
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        return pem.decode()
    
    def load_private_key(self, pem_data: str, password: Optional[bytes] = None):
        """
        Load private key from PEM format
        
        Args:
            pem_data: PEM-encoded private key
            password: Optional password for decryption
        """
        self.private_key = serialization.load_pem_private_key(
            pem_data.encode(),
            password=password,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def load_public_key(self, pem_data: str):
        """
        Load public key from PEM format
        
        Args:
            pem_data: PEM-encoded public key
        """
        self.public_key = serialization.load_pem_public_key(
            pem_data.encode(),
            backend=default_backend()
        )


if __name__ == "__main__":
    # Example usage
    signer = DNSRecordSigner()
    
    # Create a sample DNS record
    record = {
        "domain": "example.com",
        "type": "A",
        "data": "192.168.1.100",
        "ttl": 3600
    }
    
    # Sign the record
    signed_record = signer.sign_record(record)
    print("Record signed successfully!")
    print(f"Signature: {signed_record['signature'][:50]}...")
    
    # Verify the signature
    is_valid = signer.verify_signature(signed_record)
    print(f"Signature valid: {is_valid}")
    
    # Test tampering detection
    signed_record['record']['data'] = "192.168.1.101"
    is_valid = signer.verify_signature(signed_record)
    print(f"Tampered signature valid: {is_valid}")
