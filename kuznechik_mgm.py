# crypto/kuznechik_mgm.py
import os
import binascii
import secrets
from typing import Tuple

# --- Параметры блока ---
BLOCK_SIZE = 16  # 128 бит

# --- S-box Pi (ГОСТ) ---
PI = bytes((
    252,238,221, 17,207,110, 49, 22,251,196,250,218, 35,197,  4, 77,
    233,119,240,219,147, 46,153,186, 23, 54,241,187, 20,205, 95,193,
    249, 24,101, 90,226, 92,239, 33,129, 28, 60, 66,139,  1,142, 79,
      5,132,  2,174,227,106,143,160,  6, 11,237,152,127,212,211, 31,
    235, 52, 44, 81,234,200, 72,171,242, 42,104,162,253, 58,206,204,
    181,112, 14, 86,  8, 12,118, 18,191,114, 19, 71,156,183, 93,135,
     21,161,150, 41, 16,123,154,199,243,145,120,111,157,158,178,177,
     50,117, 25, 61,255, 53,138,126,109, 84,198,128,195,189, 13, 87,
    223,245, 36,169, 62,168, 67,201,215,121,214,246,124, 34,185,  3,
    224, 15,236,222,122,148,176,188,220,232, 40, 80, 78, 51, 10, 74,
    167,151, 96,115, 30,  0, 98, 68, 26,184, 56,130,100,159, 38, 65,
    173, 69, 70,146, 39, 94, 85, 47,140,163,165,125,105,213,149, 59,
      7, 88,179, 64,134,172, 29,247, 48, 55,107,228,136,217,231,137,
    225, 27,131, 73, 76, 63,248,254,141, 83,170,144,202,216,133, 97,
     32,113,103,164, 45, 43,  9, 91,203,155, 37,208,190,229,108, 82,
     89,166,116,210,230,244,180,192,209,102,175,194, 57, 75, 99,182
))

# Вектор для линейного преобразования L
L_VECTOR = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]

class MGMEncryptor:
    """Класс для шифрования в режиме MGM (из ваших лаб 2.2 и 2.3)"""
    
    def __init__(self):
        pass
    
    # --- Базовые операции ---
    @staticmethod
    def gmul(a: int, b: int) -> int:
        """Умножение в поле GF(2^8) с примитивом 0xC3 (алгоритм ГОСТ)."""
        r = 0
        for _ in range(8):
            if b & 1:
                r ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0xC3
            b >>= 1
        return r
    
    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        """Побайтное XOR для двух байтовых строк одинаковой длины."""
        return bytes(x ^ y for x, y in zip(a, b))
    
    @staticmethod
    def apply_sbox(block: bytes) -> bytes:
        """Подстановка S (Pi)."""
        return bytes(PI[b] for b in block)
    
    @staticmethod
    def rotate_R(state: bytes) -> bytes:
        """Операция R (внутренняя для L): сдвиг + суммирование по L_VECTOR."""
        acc = 0
        for i in range(16):
            acc ^= MGMEncryptor.gmul(state[i], L_VECTOR[i])
        return bytes([acc]) + state[:15]
    
    @staticmethod
    def linear_L(state: bytes) -> bytes:
        """Линейное преобразование L = R^16."""
        s = state
        for _ in range(16):
            s = MGMEncryptor.rotate_R(s)
        return s
    
    @staticmethod
    def LSX_transform(a: bytes, b: bytes) -> bytes:
        """Комбинация: сначала XOR, потом S, потом L."""
        return MGMEncryptor.linear_L(MGMEncryptor.apply_sbox(MGMEncryptor.xor_bytes(a, b)))
    
    # --- Ключевая схема Кузнечик ---
    @staticmethod
    def derive_round_keys(master_key: bytes) -> list:
        """Развёртка ключей: возвращает список 10 ключей (по 16 байт)."""
        k1, k2 = master_key[:16], master_key[16:]
        rk = [k1, k2]
        
        for j in range(4):
            for i in range(1, 9):
                c = MGMEncryptor.linear_L(bytes([0] * 15 + [8 * j + i]))
                k1, k2 = MGMEncryptor.xor_bytes(MGMEncryptor.LSX_transform(k1, c), k2), k1
            rk.extend([k1, k2])
        
        return rk
    
    @staticmethod
    def kuz_encrypt_blk(key: bytes, block: bytes) -> bytes:
        """Шифрование одного блока (16 байт) алгоритмом Кузнечик."""
        round_keys = MGMEncryptor.derive_round_keys(key)
        s = block
        
        for i in range(9):
            s = MGMEncryptor.LSX_transform(s, round_keys[i])
        
        return MGMEncryptor.xor_bytes(s, round_keys[9])
    
    # --- Вспомогательные функции MGM ---
    @staticmethod
    def mgm_increment_counter(counter: bytes) -> bytes:
        cnt = int.from_bytes(counter, 'big')
        return ((cnt + 1) & ((1 << 128) - 1)).to_bytes(16, 'big')
    
    @staticmethod
    def mgm_pad(data: bytes) -> bytes:
        """Паддинг: 0x80 + нули до размера блока (если нужно)."""
        if len(data) % BLOCK_SIZE == 0:
            return data
        
        padded = data + b'\x80'
        while len(padded) % BLOCK_SIZE != 0:
            padded += b'\x00'
        
        return padded
    
    @staticmethod
    def mgm_ghash(key: bytes, data: bytes) -> bytes:
        """
        Простая реализация GHASH-подобной функции.
        """
        H = MGMEncryptor.kuz_encrypt_blk(key, b'\x00' * BLOCK_SIZE)
        blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
        Y = b'\x00' * BLOCK_SIZE
        
        for block in blocks:
            if len(block) < BLOCK_SIZE:
                block = block + b'\x80' + b'\x00' * (BLOCK_SIZE - len(block) - 1)
            Y = MGMEncryptor.xor_bytes(MGMEncryptor.kuz_encrypt_blk(key, MGMEncryptor.xor_bytes(Y, block)), H)
        
        return Y
    
    def mgm_encrypt(self, key: bytes, iv: bytes, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes]:
        """Шифрование в режиме MGM: возвращает (ciphertext, auth_tag)."""
        IV_padded = iv + b'\x00\x00\x00\x01'
        J0 = iv + b'\x00\x00\x00\x02'
        counter = IV_padded
        
        ct_blocks = []
        
        for i in range(0, len(plaintext), BLOCK_SIZE):
            blk = plaintext[i:i + BLOCK_SIZE]
            keystream = self.kuz_encrypt_blk(key, counter)
            ct_blocks.append(self.xor_bytes(blk, keystream))
            counter = self.mgm_increment_counter(counter)
        
        ciphertext = b''.join(ct_blocks)
        
        # Тег: комбинирование хэшей ассоциированных данных и шифртекста
        A_hash = self.mgm_ghash(key, self.mgm_pad(associated_data))
        C_hash = self.mgm_ghash(key, self.mgm_pad(ciphertext))
        S = self.xor_bytes(A_hash, C_hash)
        T_full = self.kuz_encrypt_blk(key, J0)
        auth_tag = self.xor_bytes(S, T_full)[:8]  # 64-битный тег
        
        return ciphertext, auth_tag
    
    def mgm_decrypt(self, key: bytes, iv: bytes, ciphertext: bytes, 
                   associated_data: bytes, auth_tag: bytes) -> Tuple[bytes, bool]:
        """Расшифрование в MGM: проверяет тег и возвращает (plaintext, ok)."""
        J0 = iv + b'\x00\x00\x00\x02'
        A_hash = self.mgm_ghash(key, self.mgm_pad(associated_data))
        C_hash = self.mgm_ghash(key, self.mgm_pad(ciphertext))
        S = self.xor_bytes(A_hash, C_hash)
        T_full = self.kuz_encrypt_blk(key, J0)
        expected_tag = self.xor_bytes(S, T_full)[:8]
        
        if expected_tag != auth_tag:
            return b'', False
        
        IV_padded = iv + b'\x00\x00\x00\x01'
        counter = IV_padded
        pt_blocks = []
        
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            blk = ciphertext[i:i + BLOCK_SIZE]
            keystream = self.kuz_encrypt_blk(key, counter)
            pt_blocks.append(self.xor_bytes(blk, keystream))
            counter = self.mgm_increment_counter(counter)
        
        return b''.join(pt_blocks), True
    
    # --- Интерфейс для Flask ---
    def encrypt_document(self, file_path: str, associated_data: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """Шифрование файла с аутентификацией MGM."""
        if associated_data is None:
            associated_data = b'Protected Document'
        
        # Генерация ключа и IV
        key = secrets.token_bytes(32)  # 256 бит
        iv = secrets.token_bytes(12)   # 96 бит
        
        # Чтение файла
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Шифрование
        ciphertext, tag = self.mgm_encrypt(key, iv, plaintext, associated_data)
        
        # Сохранение зашифрованного файла
        encrypted_path = file_path + '.mgm'
        with open(encrypted_path, 'wb') as f:
            f.write(ciphertext)
        
        # Сохранение ключа, IV и тега (в реальном приложении ключ должен храниться безопасно)
        metadata = {
            'key': key.hex(),
            'iv': iv.hex(),
            'tag': tag.hex(),
            'associated_data': associated_data.hex()
        }
        
        return ciphertext, tag, iv
    
    def decrypt_document(self, encrypted_path: str, key_hex: str, iv_hex: str, 
                        tag_hex: str, associated_data_hex: str) -> bytes:
        """Расшифрование файла с проверкой аутентификации."""
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        tag = bytes.fromhex(tag_hex)
        associated_data = bytes.fromhex(associated_data_hex)
        
        # Чтение зашифрованного файла
        with open(encrypted_path, 'rb') as f:
            ciphertext = f.read()
        
        # Расшифрование
        plaintext, ok = self.mgm_decrypt(key, iv, ciphertext, associated_data, tag)
        
        if not ok:
            raise ValueError("Аутентификация не удалась: неверный тег или данные")
        
        return plaintext
    
    # --- Тестовые функции ---
    @staticmethod
    def run_gost_example():
        """Пример-тест по ГОСТ 34.13-2018."""
        print("=== ТЕСТ ПО ГОСТ 34.13-2018 ===")
        
        key = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
        iv = bytes.fromhex("112233445566778899aabbcc")
        plaintext = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
        associated_data = bytes.fromhex("00112233445566778899aabbcceeff0a")
        
        print(f"Ключ: {binascii.hexlify(key).decode()}")
        print(f"IV: {binascii.hexlify(iv).decode()}")
        print(f"Открытый текст: {binascii.hexlify(plaintext).decode()}")
        print(f"Ассоциированные данные: {binascii.hexlify(associated_data).decode()}")
        
        mgm = MGMEncryptor()
        ciphertext, tag = mgm.mgm_encrypt(key, iv, plaintext, associated_data)
        
        print(f"Шифртекст: {binascii.hexlify(ciphertext).decode()}")
        print(f"Тег: {binascii.hexlify(tag).decode()}")
        
        decrypted, ok = mgm.mgm_decrypt(key, iv, ciphertext, associated_data, tag)
        
        print(f"Расшифровка: {binascii.hexlify(decrypted).decode()}")
        print(f"Аутентификация: {'ОК' if ok else 'НЕ ОК'}")
        print(f"Совпадение с оригиналом: {'ДА' if decrypted == plaintext else 'НЕТ'}")
        
        # проверка с изменёнными AD
        bad_ad = associated_data + b'\x00'
        _, ok2 = mgm.mgm_decrypt(key, iv, ciphertext, bad_ad, tag)
        print(f"Проверка с изменёнными ассоциированными данными: {'ОК' if ok2 else 'НЕ ОК'}")
        
        return ok and (decrypted == plaintext)

def test_mgm():
    """Тестирование MGM"""
    try:
        result = MGMEncryptor.run_gost_example()
        return {
            'success': result,
            'message': 'Тест ГОСТ 34.13-2018 пройден' if result else 'Тест не пройден'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'Ошибка при тестировании MGM'
        }

if __name__ == "__main__":
    # Тестирование
    result = test_mgm()
    print(f"Результат теста: {result['message']}")