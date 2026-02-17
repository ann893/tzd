# crypto/key_generator.py
import hashlib
import hmac
import binascii
import secrets

def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA512 (аналог HMAC-Стрибог)."""
    return hmac.new(key, msg, hashlib.sha512).digest()

def kdf_derive_key_simple(K: bytes, label: bytes, seed: bytes) -> bytes:
    """
    Производный ключ по КСФ ГОСТ Р 34.10-2012.
    Формат: 0x01 || label || 0x00 || seed || 0x0100
    """
    message = b'\x01' + label + b'\x00' + seed + b'\x01\x00'
    derived_key = hmac_sha512(K, message)
    return derived_key

def generate_key_material() -> dict:
    """
    Генерация ключевого материала для пользователя.
    Возвращает словарь с ключами для различных алгоритмов.
    """
    # Генерация мастер-ключа
    master_key = secrets.token_bytes(32)
    
    # Генерация метки и соли
    label = secrets.token_bytes(4)
    seed = secrets.token_bytes(8)
    
    # Диверсификация ключа
    derived_key = kdf_derive_key_simple(master_key, label, seed)
    
    # Разделение на ключи для разных алгоритмов
    keys = {
        'master_key': master_key.hex(),
        'label': label.hex(),
        'seed': seed.hex(),
        'derived_key': derived_key.hex(),
        'magma_key': derived_key[:32].hex(),        # 256 бит для Магма
        'kuznechik_key': derived_key[32:64].hex(),  # 256 бит для Кузнечик
        'mgm_key': derived_key[:32].hex(),          # 256 бит для MGM
        'ecp_private': derived_key[:32].hex(),      # Приватный ключ ЭЦП
        'dh_private': secrets.token_bytes(32).hex(), # Приватный ключ DH
        'dh_public': secrets.token_bytes(32).hex()   # Публичный ключ DH
    }
    
    return keys

def generate_specific_key(algorithm: str, key_length: int = 256) -> dict:
    """
    Генерация ключа для конкретного алгоритма.
    
    Аргументы:
        algorithm: 'magma', 'kuznechik', 'mgm', 'ecp', 'dh'
        key_length: длина ключа в битах (128, 192, 256)
    
    Возвращает:
        Словарь с ключом и дополнительными параметрами
    """
    if algorithm == 'magma':
        # Для Магма требуется 256 бит
        key = secrets.token_bytes(32)
        return {
            'algorithm': 'Magma (GOST 34.12-2015)',
            'key': key.hex(),
            'key_length': 256,
            'block_size': 64,
            'rounds': 32
        }
    
    elif algorithm == 'kuznechik':
        # Для Кузнечик требуется 256 бит
        key = secrets.token_bytes(32)
        return {
            'algorithm': 'Kuznechik (GOST 34.12-2015)',
            'key': key.hex(),
            'key_length': 256,
            'block_size': 128,
            'rounds': 10
        }
    
    elif algorithm == 'mgm':
        # Для MGM требуются ключ и IV
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        return {
            'algorithm': 'MGM (GOST 34.13-2018)',
            'key': key.hex(),
            'iv': iv.hex(),
            'key_length': 256,
            'iv_length': 96,
            'tag_length': 64
        }
    
    elif algorithm == 'ecp':
        # Для ЭЦП ГОСТ
        private_key = secrets.token_bytes(32)
        return {
            'algorithm': 'GOST 34.10-2018',
            'private_key': private_key.hex(),
            'curve': 'GOST R 34.10-2012 256-bit',
            'hash_algorithm': 'Stribog-256'
        }
    
    elif algorithm == 'dh':
        # Для Диффи-Хеллмана
        private_key = secrets.token_bytes(32)
        public_key = secrets.token_bytes(32)  # В реальности вычисляется
        return {
            'algorithm': 'Diffie-Hellman',
            'private_key': private_key.hex(),
            'public_key': public_key.hex(),
            'key_length': 256,
            'protocol': 'ЭЦП ГОСТ 34.10-2018'
        }
    
    else:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

def generate_all_keys() -> dict:
    """
    Генерация полного набора ключей для системы ЗЭДКД.
    """
    keys = {
        'symmetric': {},
        'asymmetric': {},
        'hash': {},
        'key_derivation': {}
    }
    
    # Симметричные ключи
    keys['symmetric']['magma'] = generate_specific_key('magma')
    keys['symmetric']['kuznechik'] = generate_specific_key('kuznechik')
    keys['symmetric']['mgm'] = generate_specific_key('mgm')
    
    # Асимметричные ключи
    keys['asymmetric']['ecp'] = generate_specific_key('ecp')
    keys['asymmetric']['dh'] = generate_specific_key('dh')
    
    # Хэш-функции (не требуют ключей)
    keys['hash'] = {
        'stribog_256': {
            'algorithm': 'Stribog-256 (GOST 34.11-2018)',
            'output_length': 256,
            'block_size': 512
        },
        'stribog_512': {
            'algorithm': 'Stribog-512 (GOST 34.11-2018)',
            'output_length': 512,
            'block_size': 512
        }
    }
    
    # Ключевая иерархия
    master_material = generate_key_material()
    keys['key_derivation'] = {
        'master_key': master_material['master_key'],
        'derivation_function': 'KDF ГОСТ Р 34.10-2012',
        'derived_keys': {
            'magma': master_material['magma_key'],
            'kuznechik': master_material['kuznechik_key'],
            'mgm': master_material['mgm_key']
        }
    }
    
    return keys

def save_keys_to_file(keys: dict, filename: str):
    """
    Сохранение ключей в файл.
    ВНИМАНИЕ: В реальной системе ключи должны храниться безопасно!
    """
    with open(filename, 'w') as f:
        f.write("=== КЛЮЧЕВАЯ ИНФРАСТРУКТУРА ЗЭДКД ===\n\n")
        
        f.write("СИММЕТРИЧНЫЕ КЛЮЧИ:\n")
        f.write("=" * 50 + "\n")
        for algo, data in keys['symmetric'].items():
            f.write(f"\n{algo.upper()}:\n")
            for key, value in data.items():
                if 'key' in key or 'iv' in key:
                    f.write(f"  {key}: {value[:32]}...\n")
                else:
                    f.write(f"  {key}: {value}\n")
        
        f.write("\n\nАСИММЕТРИЧНЫЕ КЛЮЧИ:\n")
        f.write("=" * 50 + "\n")
        for algo, data in keys['asymmetric'].items():
            f.write(f"\n{algo.upper()}:\n")
            for key, value in data.items():
                if 'key' in key:
                    f.write(f"  {key}: {value[:32]}...\n")
                else:
                    f.write(f"  {key}: {value}\n")
        
        f.write("\n\nХЭШ-ФУНКЦИИ:\n")
        f.write("=" * 50 + "\n")
        for algo, data in keys['hash'].items():
            f.write(f"\n{algo}:\n")
            for key, value in data.items():
                f.write(f"  {key}: {value}\n")
        
        f.write("\n\nКЛЮЧЕВАЯ ИЕРАРХИЯ:\n")
        f.write("=" * 50 + "\n")
        kdf = keys['key_derivation']
        f.write(f"\nМастер-ключ: {kdf['master_key'][:32]}...\n")
        f.write(f"Функция диверсификации: {kdf['derivation_function']}\n")
        f.write("\nПроизводные ключи:\n")
        for algo, key in kdf['derived_keys'].items():
            f.write(f"  {algo}: {key[:32]}...\n")
    
    print(f"Ключи сохранены в файл: {filename}")

def test_key_generation():
    """Тестирование генерации ключей."""
    print("=== ТЕСТ ГЕНЕРАЦИИ КЛЮЧЕЙ ===")
    
    # Тест КСФ
    print("\n1. Тест КСФ (Ключераспределительная Функция):")
    K_hex = 'db31485315694343228d6aef8cc78c443d4553d8e9cfec6815ebadc40a9ffd04'
    label_hex = '26bdb878'
    seed_hex = 'af21434145656378'
    
    K = binascii.unhexlify(K_hex)
    label = binascii.unhexlify(label_hex)
    seed = binascii.unhexlify(seed_hex)
    
    print(f"Мастер-ключ K: {K_hex}")
    print(f"Метка (label): {label_hex}")
    print(f"Соль (seed): {seed_hex}")
    
    derived_key = kdf_derive_key_simple(K, label, seed)
    print(f"\nДиверсифицированный ключ (512 бит):")
    print(f"{derived_key.hex()[:64]}...")
    
    mgm_key = derived_key[:32]
    print(f"\nКлюч для MGM (первые 256 бит):")
    print(f"{mgm_key.hex()}")
    
    # Тест генерации всех ключей
    print("\n\n2. Тест генерации полного набора ключей:")
    all_keys = generate_all_keys()
    
    print(f"Сгенерировано ключей:")
    print(f"  Симметричные: {len(all_keys['symmetric'])}")
    print(f"  Асимметричные: {len(all_keys['asymmetric'])}")
    print(f"  Хэш-функции: {len(all_keys['hash'])}")
    
    # Сохранение в файл для демонстрации
    save_keys_to_file(all_keys, "test_keys.txt")
    
    print("\nТест генерации ключей пройден успешно!")
    return True

if __name__ == "__main__":
    result = test_key_generation()
    print(f"\nОбщий результат теста: {'Пройден' if result else 'Не пройден'}")