# crypto/magma.py
import binascii
import os

# === ФУНКЦИИ МАГМЫ ===
pi = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
]

MASK32 = (1 << 32) - 1

def t(x):
    y = 0
    for i in reversed(range(8)):
        j = (x >> (4 * i)) & 0xf
        y = (y << 4) | pi[i][j]
    return y

def rot11(x):
    return ((x << 11) | (x >> (32 - 11))) & MASK32

def g(x, k):
    return rot11(t((x + k) & MASK32))

def split_block(block_int):
    return (block_int >> 32) & MASK32, block_int & MASK32

def join_block(L, R):
    return ((L & MASK32) << 32) | (R & MASK32)

def magma_key_schedule(key_int):
    keys = []
    for i in reversed(range(8)):
        keys.append((key_int >> (32 * i)) & MASK32)
    
    round_keys = []
    round_keys.extend(keys)          # 1-8
    round_keys.extend(keys)          # 9-16
    round_keys.extend(keys)          # 17-24
    round_keys.extend(reversed(keys)) # 25-32
    
    return round_keys

def magma_encrypt_block(plain_int, round_keys):
    L, R = split_block(plain_int)
    for i in range(31):
        L, R = R, L ^ g(R, round_keys[i])
    L = L ^ g(R, round_keys[31])
    return join_block(L, R)

def magma_decrypt_block(cipher_int, round_keys):
    L, R = split_block(cipher_int)
    for i in range(31, 0, -1):
        L, R = R, L ^ g(R, round_keys[i])
    L = L ^ g(R, round_keys[0])
    return join_block(L, R)

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===
def apply_padding(data):
    pad_len = 8 - (len(data) % 8)
    if pad_len == 0:
        pad_len = 8
    return data + bytes([pad_len] * pad_len)

def strip_padding(data):
    if not data:
        return data
    pad_len = data[-1]
    if not (1 <= pad_len <= 8):
        raise ValueError("Некорректный padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Некорректный padding")
    return data[:-pad_len]

def load_binary_file(path):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        raise Exception(f"Ошибка чтения файла: {e}")

def save_binary_file(path, data):
    try:
        with open(path, 'wb') as f:
            f.write(data)
        return True
    except Exception as e:
        raise Exception(f"Ошибка записи файла: {e}")

# === ОСНОВНЫЕ ФУНКЦИИ ДЛЯ FLASK ===
def encrypt_file_magma(input_path, output_path, key_hex):
    """Шифрование файла алгоритмом Магма"""
    if len(key_hex) != 64:
        raise ValueError("Ключ должен быть 64 hex-символа (32 байта)")
    
    try:
        key_int = int(key_hex, 16)
    except ValueError:
        raise ValueError("Некорректный hex-формат ключа")
    
    data = load_binary_file(input_path)
    padded_data = apply_padding(data)
    
    round_keys = magma_key_schedule(key_int)
    encrypted = bytearray()
    
    for i in range(0, len(padded_data), 8):
        block = padded_data[i:i+8]
        if len(block) < 8:
            raise RuntimeError("Ошибка padding")
        block_int = int.from_bytes(block, 'big')
        enc_int = magma_encrypt_block(block_int, round_keys)
        encrypted.extend(enc_int.to_bytes(8, 'big'))
    
    save_binary_file(output_path, encrypted)
    return output_path

def decrypt_file_magma(input_path, output_path, key_hex):
    """Расшифрование файла алгоритмом Магма"""
    if len(key_hex) != 64:
        raise ValueError("Ключ должен быть 64 hex-символа (32 байта)")
    
    try:
        key_int = int(key_hex, 16)
    except ValueError:
        raise ValueError("Некорректный hex-формат ключа")
    
    data = load_binary_file(input_path)
    
    if len(data) % 8 != 0:
        raise ValueError("Размер зашифрованного файла должен быть кратен 8 байтам")
    
    round_keys = magma_key_schedule(key_int)
    decrypted = bytearray()
    
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        block_int = int.from_bytes(block, 'big')
        dec_int = magma_decrypt_block(block_int, round_keys)
        decrypted.extend(dec_int.to_bytes(8, 'big'))
    
    try:
        unpadded = strip_padding(decrypted)
    except ValueError as e:
        raise ValueError(f"Ошибка при удалении padding: {e}")
    
    save_binary_file(output_path, unpadded)
    return output_path

def test_magma():
    """Тестирование алгоритма Магма"""
    test_pt = '92def06b3c130a59'
    test_key = 'ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
    expected_ct = '2b073f0494f372a0'
    
    try:
        pt_int = int(test_pt, 16)
        key_int = int(test_key, 16)
        
        round_keys = magma_key_schedule(key_int)
        ct_int = magma_encrypt_block(pt_int, round_keys)
        ct_hex = format(ct_int, '016x')
        
        success = ct_hex == expected_ct
        
        return {
            'success': success,
            'plaintext': test_pt,
            'key': test_key[:32] + '...',
            'expected': expected_ct,
            'actual': ct_hex,
            'message': 'Тест ГОСТ пройден' if success else 'Тест ГОСТ не пройден'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'Ошибка при тестировании'
        }

# === КОНСОЛЬНЫЙ ИНТЕРФЕЙС (из вашей лабы) ===
def main():
    print('Выберите операцию:')
    print('1. Зашифровать файл')
    print('2. Расшифровать файл')
    print('3. Тестирование алгоритма (один 8-байтовый блок в hex)')
    choice = input().strip()
    
    if choice == '1':
        file_path = input('Укажите путь к файлу для шифрования: ').strip()
        key_hex = input('Введите ключ шифрования (hex, 64 символа): ').strip()
        
        try:
            output_path = file_path + '.encrypted'
            encrypt_file_magma(file_path, output_path, key_hex)
            print(f'Файл успешно зашифрован: {output_path}')
        except Exception as e:
            print(f'Ошибка: {e}')
    
    elif choice == '2':
        file_path = input('Укажите путь к зашифрованному файлу: ').strip()
        key_hex = input('Введите ключ расшифровки (hex, 64 символа): ').strip()
        
        try:
            if file_path.endswith('.encrypted'):
                base = file_path[:-10]
                name, ext = os.path.splitext(base)
                output_path = name + "_DECRYPTED" + ext
            else:
                name, ext = os.path.splitext(file_path)
                output_path = name + "_DECRYPTED" + ext
            
            decrypt_file_magma(file_path, output_path, key_hex)
            print(f'Файл успешно расшифрован: {output_path}')
        except Exception as e:
            print(f'Ошибка: {e}')
    
    elif choice == '3':
        pt_hex = input('Введите открытый текст (hex, 16 символов): ').strip().lower()
        key_hex = input('Введите ключ (hex, 64 символов): ').strip().lower()
        
        if len(pt_hex) != 16:
            print("Ошибка: текст должен быть 8 байт (16 hex-символов)")
            return
        
        if len(key_hex) != 64:
            print("Ошибка: ключ должен быть 32 байта (64 hex-символа)")
            return
        
        try:
            pt_int = int(pt_hex, 16)
            key_int = int(key_hex, 16)
        except ValueError:
            print("Ошибка: некорректный hex-формат")
            return
        
        round_keys = magma_key_schedule(key_int)
        ct_int = magma_encrypt_block(pt_int, round_keys)
        ct_hex = format(ct_int, '016x')
        
        print('Полученный шифртекст (hex):', ct_hex)
        
        # Тестовый вектор из стандарта ГОСТ Р 34.12-2015
        test_pt = '92def06b3c130a59'
        test_key = 'ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        expected_ct = '2b073f0494f372a0'
        
        if pt_hex == test_pt and key_hex == test_key:
            print('Ожидаемый результат по стандарту:', expected_ct)
            print('Результат проверки:', 'УСПЕХ' if ct_hex == expected_ct else 'НЕУДАЧА')
    
    else:
        print('Неизвестная операция')

if __name__ == "__main__":
    main()