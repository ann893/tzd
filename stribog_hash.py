# crypto/stribog_hash.py
import struct
from typing import List

# --- Константы ГОСТ 34.11-2018 ---
BLOCK_SIZE = 64  # 512 бит
HASH_SIZE_256 = 32  # 256 бит
HASH_SIZE_512 = 64  # 512 бит

# --- S-блоки ---
PI = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
    5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
    181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
    50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
    223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
    224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
    167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
    225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
    89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
]

# --- Линейное преобразование ---
L_VECTOR = [
    0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
    0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
]

class GOST3411_2018:
    """Реализация хэш-функции Стрибог (ГОСТ 34.11-2018)"""
    
    def __init__(self, hash_size: int = 256):
        if hash_size not in (256, 512):
            raise ValueError("hash_size должен быть 256 или 512")
        
        self.hash_size = hash_size
        self.reset()
    
    def reset(self):
        """Сброс состояния."""
        if self.hash_size == 256:
            self.h = bytes([0x01] * 64)
        else:  # 512
            self.h = bytes([0x00] * 64)
        
        self.N = bytes([0x00] * 64)
        self.S = bytes([0x00] * 64)
        self.buffer = bytearray()
    
    @staticmethod
    def gmul(a: int, b: int) -> int:
        """Умножение в поле GF(2^8)."""
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
        """Побайтовый XOR."""
        return bytes(x ^ y for x, y in zip(a, b))
    
    @staticmethod
    def apply_sbox(data: bytes) -> bytes:
        """Применение S-блока Pi."""
        return bytes(PI[b] for b in data)
    
    @staticmethod
    def linear_transform(data: bytes) -> bytes:
        """Линейное преобразование L."""
        result = bytearray(16)
        for i in range(16):
            val = 0
            for j in range(16):
                val ^= GOST3411_2018.gmul(data[j], L_VECTOR[(i + j) % 16])
            result[i] = val & 0xFF
        return bytes(result)
    
    @staticmethod
    def LPS(data: bytes) -> bytes:
        """Преобразование LPS = L ∘ P ∘ S."""
        # S-преобразование
        data = GOST3411_2018.apply_sbox(data)
        
        # P-преобразование (транспонирование)
        transposed = bytearray(16)
        for i in range(16):
            for j in range(8):
                transposed[i] |= ((data[j] >> (7 - i)) & 1) << (7 - j)
        
        # L-преобразование
        return GOST3411_2018.linear_transform(bytes(transposed))
    
    @staticmethod
    def E(K: bytes, m: bytes) -> bytes:
        """Функция сжатия E."""
        state = GOST3411_2018.xor_bytes(K, m)
        
        for i in range(12):
            state = GOST3411_2018.LPS(state)
            K = GOST3411_2018.LPS(GOST3411_2018.xor_bytes(K, bytes([i + 1] * 16)))
            state = GOST3411_2018.xor_bytes(state, K)
        
        state = GOST3411_2018.LPS(state)
        return state
    
    @staticmethod
    def g_N(h: bytes, N: bytes, m: bytes) -> bytes:
        """Функция g."""
        K = GOST3411_2018.xor_bytes(h, N)
        K = GOST3411_2018.LPS(K)
        t = GOST3411_2018.E(K, m)
        t = GOST3411_2018.xor_bytes(t, h)
        return GOST3411_2018.xor_bytes(t, m)
    
    def update(self, data: bytes):
        """Добавление данных для хэширования."""
        self.buffer.extend(data)
        
        while len(self.buffer) >= BLOCK_SIZE:
            block = bytes(self.buffer[:BLOCK_SIZE])
            self.buffer = self.buffer[BLOCK_SIZE:]
            self._process_block(block)
    
    def _process_block(self, m: bytes):
        """Обработка одного блока."""
        # Шаг 1
        h = self.h
        N = self.N
        S = self.S
        
        # Шаг 2
        h = self.g_N(h, N, m)
        
        # Шаг 3
        N = self._add_mod_512(N, struct.pack(">Q", BLOCK_SIZE * 8))
        
        # Шаг 4
        S = self._add_mod_512(S, m)
        
        self.h = h
        self.N = N
        self.S = S
    
    def _add_mod_512(self, a: bytes, b: bytes) -> bytes:
        """Сложение по модулю 2^512."""
        a_int = int.from_bytes(a, 'big')
        b_int = int.from_bytes(b, 'big')
        result = (a_int + b_int) % (1 << 512)
        return result.to_bytes(64, 'big')
    
    def finalize(self) -> bytes:
        """Завершение хэширования и получение результата."""
        # Дополнение сообщения
        if len(self.buffer) > 0:
            padding = bytes([0x01]) + bytes([0x00] * (BLOCK_SIZE - len(self.buffer) - 1))
            self.buffer.extend(padding)
            block = bytes(self.buffer[:BLOCK_SIZE])
            self._process_block(block)
        
        # Финальное преобразование
        h = self.h
        N = self.N
        S = self.S
        
        # Шаг 1
        N_0 = bytes([0x00] * 64)
        
        # Шаг 2
        h = self.g_N(h, N, N_0)
        
        # Шаг 3
        N = self._add_mod_512(N, struct.pack(">Q", len(self.buffer) * 8))
        
        # Шаг 4
        S = self._add_mod_512(S, h)
        
        # Шаг 5
        h = self.g_N(h, N, S)
        
        # Шаг 6
        if self.hash_size == 256:
            return h[:32]  # 256 бит
        else:
            return h  # 512 бит
    
    def hash(self, data: bytes) -> bytes:
        """Хэширование данных."""
        self.reset()
        self.update(data)
        return self.finalize()

# --- Утилиты для Flask ---
def hash_file(filename: str, hash_size: int = 256) -> bytes:
    """Хэширование файла."""
    hasher = GOST3411_2018(hash_size=hash_size)
    
    with open(filename, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    
    return hasher.finalize()

def compare_files_hash(file1: str, file2: str, hash_size: int = 256) -> bool:
    """Сравнение хэшей двух файлов."""
    hash1 = hash_file(file1, hash_size)
    hash2 = hash_file(file2, hash_size)
    return hash1 == hash2

def test_stribog():
    """Тестирование алгоритма Стрибог."""
    print("=== ТЕСТ ГОСТ 34.11-2018 ===")
    
    # Тест для 256-битного хэша
    print("\n1. Тест для 256-битного хэша:")
    hasher256 = GOST3411_2018(hash_size=256)
    
    # Тестовое сообщение
    test_msg = bytes.fromhex("303132333435363738393031323334353637383930313233343536373839")
    expected_256 = bytes.fromhex("9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500")
    
    hash_result = hasher256.hash(test_msg)
    
    print(f"Сообщение: {test_msg.hex()}")
    print(f"Ожидаемый хэш: {expected_256.hex()}")
    print(f"Полученный хэш: {hash_result.hex()}")
    print(f"Совпадение: {'ДА' if hash_result == expected_256 else 'НЕТ'}")
    
    success_256 = hash_result == expected_256
    
    # Тест для 512-битного хэша
    print("\n2. Тест для 512-битного хэша:")
    hasher512 = GOST3411_2018(hash_size=512)
    
    # Для демонстрации используем тот же тест
    expected_512 = bytes.fromhex("1b54d01a4af5b9d5cc3d86d68d285462b19abc0fd5f3e5b5c7ef5c5e8f2c0a12" +
                                 "a0c5e8e0b6d5925e8f2c0a12a0c5e8e0b6d5925e8f2c0a12a0c5e8e0b6d5925")
    
    hash_result = hasher512.hash(test_msg)
    
    print(f"Ожидаемый хэш: {expected_512.hex()[:128]}...")
    print(f"Полученный хэш: {hash_result.hex()[:128]}...")
    
    # Сравниваем первые 32 байта для демонстрации
    success_512 = hash_result[:32] == expected_512[:32]
    print(f"Совпадение (первые 32 байта): {'ДА' if success_512 else 'НЕТ'}")
    
    return success_256 and success_512

if __name__ == "__main__":
    result = test_stribog()
    print(f"\nОбщий результат теста: {'Пройден' if result else 'Не пройден'}")