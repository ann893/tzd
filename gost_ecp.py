# crypto/gost_ecp.py
import secrets
import os
import hashlib
from typing import Tuple, Optional

class Stribog:
    """Упрощенная реализация Stribog для ЭЦП"""
    
    def __init__(self, hash_size: int = 512):
        if hash_size not in (256, 512):
            raise ValueError("hash_size должен быть 256 или 512")
        
        self.hash_size = hash_size
        self.buffer = bytearray()
        self.h = bytearray(64)
        self.N = bytearray(64)
        self.Sigma = bytearray(64)
        
        if hash_size == 256:
            self.h = bytearray([1] + [0] * 63)
    
    def _add_modulo_2_512(self, a: bytearray, b: bytearray) -> bytearray:
        res = bytearray(64)
        carry = 0
        for i in range(63, -1, -1):
            s = a[i] + b[i] + carry
            res[i] = s & 0xFF
            carry = s >> 8
        return res
    
    def _S(self, data: bytearray) -> bytearray:
        # Упрощенная S-бокс
        return bytearray((b + 1) % 256 for b in data)
    
    def _P(self, data: bytearray) -> bytearray:
        # Упрощенная перестановка
        res = bytearray(64)
        for i in range(64):
            res[(i * 7) % 64] = data[i]
        return res
    
    def _L(self, data: bytearray) -> bytearray:
        # Упрощенное линейное преобразование
        res = bytearray(64)
        for i in range(64):
            v = data[i]
            res[i] = ((v << 1) ^ (v >> 1)) & 0xFF
        return res
    
    def _LPS(self, data: bytearray) -> bytearray:
        return self._L(self._P(self._S(data)))
    
    def update(self, data: bytes) -> None:
        self.buffer.extend(data)
        while len(self.buffer) >= 64:
            block = self.buffer[:64]
            self.buffer = self.buffer[64:]
            
            # Упрощенная обработка блока
            for i in range(64):
                self.h[i] ^= block[i]
    
    def finalize(self) -> bytes:
        # Дополнение
        if len(self.buffer) < 64:
            pad = bytearray(self.buffer)
            pad.append(0x01)
            pad.extend(b"\x00" * (64 - len(pad)))
            block = pad
        else:
            block = bytearray(self.buffer[:64])
        
        # Обработка последнего блока
        for i in range(64):
            self.h[i] ^= block[i]
        
        if self.hash_size == 256:
            return bytes(self.h[32:])
        return bytes(self.h)
    
    def hash(self, data: bytes) -> bytes:
        self.__init__(self.hash_size)
        self.update(data)
        return self.finalize()

class GOST3410_2018:
    """Реализация ЭЦП ГОСТ 34.10-2018 (упрощенная)"""
    
    def __init__(self):
        # Упрощенные параметры для демонстрации
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
        self.a = -3
        self.b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
        self.q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
        
        # Базовая точка (упрощенно)
        self.P = (
            0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
            0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
        )
        
        # Хэш-функция
        self.hasher = Stribog(256)
    
    def mod_inverse(self, a: int, m: int) -> int:
        """Обратный элемент по модулю."""
        return pow(a, -1, m)
    
    def point_add(self, P1: Optional[Tuple[int, int]], P2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """Сложение точек эллиптической кривой."""
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        
        x1, y1 = P1
        x2, y2 = P2
        
        if x1 == x2 and y1 == y2:
            # Удвоение
            lam = (3 * x1 * x1 + self.a) * self.mod_inverse(2 * y1, self.p) % self.p
        else:
            # Сложение разных точек
            lam = (y2 - y1) * self.mod_inverse(x2 - x1, self.p) % self.p
        
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        
        return (x3, y3)
    
    def point_mult(self, k: int, P: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        """Умножение точки на скаляр."""
        R = None
        add = P
        
        while k > 0:
            if k & 1:
                R = self.point_add(R, add)
            add = self.point_add(add, add)
            k >>= 1
        
        return R
    
    def generate_key_pair(self) -> Tuple[int, Tuple[int, int]]:
        """Генерация пары ключей."""
        private_key = secrets.randbelow(self.q - 1) + 1
        public_key = self.point_mult(private_key, self.P)
        return private_key, public_key
    
    def sign_message(self, message: bytes, private_key: int) -> Tuple[int, int]:
        """Создание цифровой подписи."""
        # Хэш сообщения
        h_bytes = self.hasher.hash(message)
        h = int.from_bytes(h_bytes, "big") % self.q
        
        if h == 0:
            h = 1
        
        # Генерация подписи
        while True:
            k = secrets.randbelow(self.q - 1) + 1
            C = self.point_mult(k, self.P)
            
            if C is None:
                continue
            
            r = C[0] % self.q
            
            if r == 0:
                continue
            
            s = (r * private_key + k * h) % self.q
            
            if s != 0:
                return (r, s)
    
    def verify_signature(self, message: bytes, signature: Tuple[int, int], 
                        public_key: Tuple[int, int]) -> bool:
        """Проверка цифровой подписи."""
        r, s = signature
        
        # Проверка диапазонов
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        
        # Хэш сообщения
        h_bytes = self.hasher.hash(message)
        h = int.from_bytes(h_bytes, "big") % self.q
        
        if h == 0:
            h = 1
        
        # Вычисление вспомогательных величин
        v = self.mod_inverse(h, self.q)
        z1 = (s * v) % self.q
        z2 = (-r * v) % self.q
        
        # Точка C = z1 * P + z2 * Q
        C1 = self.point_mult(z1, self.P)
        C2 = self.point_mult(z2, public_key)
        C = self.point_add(C1, C2)
        
        if C is None:
            return False
        
        R = C[0] % self.q
        return R == r

# --- Утилиты для Flask ---
def create_signature_file(data: bytes, private_key: int, output_path: str) -> Tuple[int, int]:
    """Создание подписи и сохранение в файл."""
    gost = GOST3410_2018()
    signature = gost.sign_message(data, private_key)
    
    with open(output_path, "w") as f:
        f.write(f"r: {hex(signature[0])}\n")
        f.write(f"s: {hex(signature[1])}\n")
        f.write(f"algorithm: GOST 34.10-2018\n")
    
    return signature

def verify_signature_file(data: bytes, signature_path: str, public_key: Tuple[int, int]) -> bool:
    """Проверка подписи из файла."""
    gost = GOST3410_2018()
    
    try:
        with open(signature_path, "r") as f:
            lines = f.readlines()
        
        r = int(lines[0].split(":")[1].strip(), 16)
        s = int(lines[1].split(":")[1].strip(), 16)
        
        signature = (r, s)
        return gost.verify_signature(data, signature, public_key)
    except:
        return False

def test_gost_signature():
    """Тестирование ЭЦП ГОСТ."""
    print("=== ТЕСТ ЭЦП ГОСТ 34.10-2018 ===")
    
    gost = GOST3410_2018()
    
    # Генерация ключей
    private_key, public_key = gost.generate_key_pair()
    print(f"Приватный ключ: {hex(private_key)[:20]}...")
    print(f"Публичный ключ: ({hex(public_key[0])[:20]}..., {hex(public_key[1])[:20]}...)")
    
    # Тестовое сообщение
    message = b"Test message for GOST 34.10-2018 signature"
    print(f"\nСообщение: {message[:20]}...")
    
    # Создание подписи
    signature = gost.sign_message(message, private_key)
    print(f"\nПодпись создана:")
    print(f"r: {hex(signature[0])}")
    print(f"s: {hex(signature[1])}")
    
    # Проверка подписи
    is_valid = gost.verify_signature(message, signature, public_key)
    print(f"\nПроверка подписи: {'УСПЕХ' if is_valid else 'НЕУДАЧА'}")
    
    # Проверка с измененным сообщением
    wrong_message = b"Wrong message for GOST signature"
    is_valid_wrong = gost.verify_signature(wrong_message, signature, public_key)
    print(f"Проверка с измененным сообщением: {'ОШИБОЧНО ПРИНЯТА' if is_valid_wrong else 'КОРРЕКТНО ОТВЕРГНУТА'}")
    
    return is_valid and not is_valid_wrong

if __name__ == "__main__":
    result = test_gost_signature()
    print(f"\nОбщий результат теста: {'Пройден' if result else 'Не пройден'}")