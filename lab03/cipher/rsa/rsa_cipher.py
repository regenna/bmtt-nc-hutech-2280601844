import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

class RSACipher:
    def __init__(self):
        self.private_key_path = os.path.join(os.path.dirname(__file__), 'keys', 'private_key.pem')
        self.public_key_path = os.path.join(os.path.dirname(__file__), 'keys', 'public_key.pem')
    
    def generate_keys(self):
        """
        Tạo cặp khóa RSA và lưu vào thư mục keys
        
        Returns:
            bool: True nếu tạo khóa thành công, False nếu có lỗi
        """
        try:
            # Tạo thư mục keys nếu chưa tồn tại
            os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)
            
            # Tạo private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Lấy public key từ private key
            public_key = private_key.public_key()
            
            # Lưu private key
            with open(self.private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Lưu public key
            with open(self.public_key_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            return True
        except Exception as e:
            print(f"Lỗi khi tạo khóa: {str(e)}")
            return False
    
    def load_keys(self):
        """
        Đọc cả private key và public key từ file
        
        Returns:
            tuple: (private_key, public_key)
        """
        private_key = self.load_private_key()
        public_key = self.load_public_key()
        return private_key, public_key
    
    def load_public_key(self):
        """
        Đọc public key từ file
        
        Returns:
            object: Public key object
        """
        try:
            with open(self.public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            return public_key
        except Exception as e:
            print(f"Lỗi khi đọc public key: {str(e)}")
            return None
    
    def load_private_key(self):
        """
        Đọc private key từ file
        
        Returns:
            object: Private key object
        """
        try:
            with open(self.private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            return private_key
        except Exception as e:
            print(f"Lỗi khi đọc private key: {str(e)}")
            return None
    
    def encrypt(self, message, key=None):
        """
        Mã hóa văn bản bằng key (mặc định là public key)
        
        Args:
            message (str): Văn bản cần mã hóa
            key (object, optional): Khóa để mã hóa. Mặc định sẽ sử dụng public key từ file.
            
        Returns:
            bytes: Văn bản đã mã hóa
        """
        try:
            if key is None:
                key = self.load_public_key()
                
            if not key:
                return None
            
            # Mã hóa văn bản
            encrypted = key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return encrypted
        except Exception as e:
            print(f"Lỗi khi mã hóa: {str(e)}")
            return None
    
    def decrypt(self, ciphertext, key=None):
        """
        Giải mã văn bản bằng key (mặc định là private key)
        
        Args:
            ciphertext (bytes): Văn bản đã mã hóa
            key (object, optional): Khóa để giải mã. Mặc định sẽ sử dụng private key từ file.
            
        Returns:
            str: Văn bản đã giải mã
        """
        try:
            if key is None:
                key = self.load_private_key()
                
            if not key:
                return None
            
            # Giải mã văn bản
            decrypted = key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Lỗi khi giải mã: {str(e)}")
            return None
    
    def sign(self, message, key=None):
        """
        Ký văn bản bằng private key
        
        Args:
            message (str): Văn bản cần ký
            key (object, optional): Khóa để ký. Mặc định sẽ sử dụng private key từ file.
            
        Returns:
            bytes: Chữ ký
        """
        try:
            if key is None:
                key = self.load_private_key()
                
            if not key:
                return None
            
            # Ký văn bản
            signature = key.sign(
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return signature
        except Exception as e:
            print(f"Lỗi khi ký văn bản: {str(e)}")
            return None
    def verify(self, message, signature, key=None):
        """
        Xác thực chữ ký
        
        Args:
            message (str): Văn bản gốc
            signature (bytes or str): Chữ ký dạng bytes hoặc chuỗi hex
            key (object or tuple, optional): Khóa để xác thực.
                
        Returns:
            bool: True nếu chữ ký hợp lệ, False nếu không hợp lệ
        """
        try:
            # Xử lý key là một RSAPrivateKey (nhận từ API không đúng)
            if hasattr(key, 'public_key'):
                # Đây là private key, chuyển đổi thành public key
                key = key.public_key()
            # Nếu key là tuple (từ load_keys), lấy public_key
            elif isinstance(key, tuple) and len(key) >= 2:
                # Phương thức load_keys trả về (private_key, public_key)
                key = key[1]  # Lấy public_key từ tuple
                
            if key is None:
                key = self.load_public_key()
                
            if not key:
                return False
            
            # Chuyển đổi chuỗi hex thành bytes nếu cần
            if isinstance(signature, str):
                try:
                    signature = bytes.fromhex(signature)
                except ValueError:
                    # Nếu không phải hex, thử decode base64
                    try:
                        signature = base64.b64decode(signature)
                    except Exception:
                        print("Không thể chuyển đổi chuỗi thành bytes")
                        return False
            
            # Xác thực chữ ký
            key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Nếu không có exception, chữ ký hợp lệ
            return True
        except InvalidSignature:
            # Chữ ký không hợp lệ
            return False
        except Exception as e:
            print(f"Lỗi khi xác thực chữ ký: {str(e)}")
            return False
 