# crypto/diffie_elgamal.py
import secrets
import hashlib
from math import gcd
from typing import Tuple

class DHExchange:
    """Реализация обмена ключами по алгоритму Диффи-Хеллмана"""
    
    def __init__(self):
        # Используем стандартные безопасные простые числа для демонстрации
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.g = 2  # Генератор
        
    def generate_key_pair(self) -> Tuple[int, int]:
        """Генерация пары ключей."""
        private_key = secrets.randbelow(self.p - 2) + 1
        public_key = pow(self.g, private_key, self.p)
        return private_key, public_key
    
    def compute_shared_secret(self, private_key: int, other_public_key: int) -> int:
        """Вычисление общего секретного ключа."""
        shared_secret = pow(other_public_key, private_key, self.p)
        return shared_secret
    
    def derive_key_from_secret(self, shared_secret: int, key_length: int = 32) -> bytes:
        """Производный ключ из общего секрета."""
        # Используем HKDF-like схему
        salt = b'diffie-hellman-key-derivation'
        info = b'gost-document-flow-key'
        
        # PRK = HMAC-Hash(salt, shared_secret)
        prk = hashlib.pbkdf2_hmac(
            'sha256',
            str(shared_secret).encode(),
            salt,
            10000,
            key_length
        )
        
        return prk

class ElGamalSignature:
    """Реализация цифровой подписи Эль-Гамаля"""
    
    def __init__(self):
        # Простое число для демонстрации
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.g = 2  # Генератор
    
    def generate_key_pair(self) -> Tuple[int, int]:
        """Генерация пары ключей Эль-Гамаля."""
        private_key = secrets.randbelow(self.p - 2) + 1
        public_key = pow(self.g, private_key, self.p)
        return private_key, public_key
    
    def sign(self, message: bytes, private_key: int) -> Tuple[int, int]:
        """Создание цифровой подписи."""
        # Хэш сообщения
        h = int.from_bytes(hashlib.sha256(message).digest(), 'big') % (self.p - 1)
        
        if h == 0:
            h = 1
        
        # Поиск k взаимно простого с p-1
        while True:
            k = secrets.randbelow(self.p - 2) + 1
            if gcd(k, self.p - 1) == 1:
                break
        
        # Вычисление компонентов подписи
        r = pow(self.g, k, self.p)
        
        # Вычисление s
        k_inv = pow(k, -1, self.p - 1)
        s = ((h - private_key * r) * k_inv) % (self.p - 1)
        
        return (r, s)
    
    def verify(self, message: bytes, signature: Tuple[int, int], public_key: int) -> bool:
        """Проверка цифровой подписи."""
        r, s = signature
        
        # Проверка диапазонов
        if not (0 < r < self.p and 0 < s < self.p - 1):
            return False
        
        # Хэш сообщения
        h = int.from_bytes(hashlib.sha256(message).digest(), 'big') % (self.p - 1)
        
        if h == 0:
            h = 1
        
        # Проверка подписи
        left_side = (pow(public_key, r, self.p) * pow(r, s, self.p)) % self.p
        right_side = pow(self.g, h, self.p)
        
        return left_side == right_side

class CombinedCryptoSystem:
    """Комбинированная система: DH + Эль-Гамаль"""
    
    def __init__(self):
        self.dh = DHExchange()
        self.elgamal = ElGamalSignature()
    
    def generate_user_keys(self) -> dict:
        """Генерация полного набора ключей для пользователя."""
        # DH ключи
        dh_private, dh_public = self.dh.generate_key_pair()
        
        # Эль-Гамаль ключи
        eg_private, eg_public = self.elgamal.generate_key_pair()
        
        return {
            'dh': {
                'private': dh_private,
                'public': dh_public
            },
            'elgamal': {
                'private': eg_private,
                'public': eg_public
            }
        }
    
    def establish_shared_secret(self, user1_keys: dict, user2_public_dh: int) -> bytes:
        """Установка общего секретного ключа."""
        shared_secret = self.dh.compute_shared_secret(
            user1_keys['dh']['private'],
            user2_public_dh
        )
        
        # Производный ключ
        derived_key = self.dh.derive_key_from_secret(shared_secret)
        
        return derived_key
    
    def sign_and_encrypt(self, message: bytes, user_keys: dict, shared_key: bytes) -> dict:
        """Подписание и шифрование сообщения."""
        # Подписание
        signature = self.elgamal.sign(message, user_keys['elgamal']['private'])
        
        # Простое шифрование XOR для демонстрации
        encrypted = bytearray()
        for i, byte in enumerate(message):
            key_byte = shared_key[i % len(shared_key)]
            encrypted.append(byte ^ key_byte)
        
        return {
            'signature': signature,
            'encrypted_message': bytes(encrypted),
            'public_key': user_keys['elgamal']['public']
        }
    
    def decrypt_and_verify(self, encrypted_data: dict, shared_key: bytes, 
                          sender_public_key: int) -> Tuple[bytes, bool]:
        """Расшифрование и проверка сообщения."""
        # Расшифрование
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_data['encrypted_message']):
            key_byte = shared_key[i % len(shared_key)]
            decrypted.append(byte ^ key_byte)
        
        message = bytes(decrypted)
        
        # Проверка подписи
        is_valid = self.elgamal.verify(
            message,
            encrypted_data['signature'],
            sender_public_key
        )
        
        return message, is_valid

def test_diffie_elgamal():
    """Тестирование комбинированной системы DH + Эль-Гамаль."""
    print("=== TEST DIFFIE-HELLMAN + ELGAMAL ===")
    
    system = CombinedCryptoSystem()
    
    # Генерация ключей для двух пользователей
    print("\n1. Key generation:")
    user1_keys = system.generate_user_keys()
    user2_keys = system.generate_user_keys()
    
    print(f"User 1:")
    print(f"  DH public: {hex(user1_keys['dh']['public'])[:20]}...")
    print(f"  ElGamal public: {hex(user1_keys['elgamal']['public'])[:20]}...")
    
    print(f"\nUser 2:")
    print(f"  DH public: {hex(user2_keys['dh']['public'])[:20]}...")
    print(f"  ElGamal public: {hex(user2_keys['elgamal']['public'])[:20]}...")
    
    # Установка общего секрета
    print("\n\n2. Shared secret establishment:")
    shared_key1 = system.establish_shared_secret(user1_keys, user2_keys['dh']['public'])
    shared_key2 = system.establish_shared_secret(user2_keys, user1_keys['dh']['public'])
    
    print(f"User 1 shared key: {shared_key1.hex()[:32]}...")
    print(f"User 2 shared key: {shared_key2.hex()[:32]}...")
    print(f"Keys match: {'YES' if shared_key1 == shared_key2 else 'NO'}")
    
    # Подписание и шифрование
    print("\n\n3. Message signing and encryption:")
    message = b"Important confidential document for ZEDKD"
    print(f"Original message: {message[:30]}...")
    
    encrypted_data = system.sign_and_encrypt(message, user1_keys, shared_key1)
    print(f"Encrypted message: {encrypted_data['encrypted_message'].hex()[:64]}...")
    print(f"Signature: r={hex(encrypted_data['signature'][0])[:20]}..., s={hex(encrypted_data['signature'][1])[:20]}...")
    
    # Расшифрование и проверка
    print("\n\n4. Decryption and verification:")
    decrypted_message, is_valid = system.decrypt_and_verify(
        encrypted_data, 
        shared_key2, 
        user1_keys['elgamal']['public']
    )
    
    print(f"Decrypted message: {decrypted_message[:30]}...")
    print(f"Signature verification: {'VALID' if is_valid else 'INVALID'}")
    print(f"Message matches original: {'YES' if message == decrypted_message else 'NO'}")
    
    # Попытка подмены
    print("\n\n5. Tamper test:")
    # Создаем поддельное сообщение
    fake_message = b"Fake message for testing"
    fake_encrypted = system.sign_and_encrypt(fake_message, user2_keys, shared_key2)
    
    # Пытаемся проверить подпись пользователя 1 на поддельном сообщении
    _, fake_valid = system.decrypt_and_verify(
        fake_encrypted,
        shared_key1,
        user1_keys['elgamal']['public']  # Неправильный публичный ключ
    )
    
    print(f"Fake signature verification: {'WRONGLY ACCEPTED' if fake_valid else 'CORRECTLY REJECTED'}")
    
    success = (
        shared_key1 == shared_key2 and
        message == decrypted_message and
        is_valid and
        not fake_valid
    )
    
    return success

if __name__ == "__main__":
    result = test_diffie_elgamal()
    print(f"\n\nOverall test result: {'PASSED' if result else 'FAILED'}")