import hashlib
import hmac
from math import ceil

hash_len = 32


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(length: int, ikm, salt: bytes = b"", CTXinfo: bytes = b"") -> bytes:
    # соль - опциональное поле, поэтому, если не задано пользователем,
    # используем строку нулей длины hash_len:
    if len(salt) == 0:
        salt = bytes([0] * hash_len)

    # Первый шаг: из предоставленного ключа генерируем псевдослучайный ключ
    # с помощью хэш-функции:
    prk = hmac_sha256(salt, ikm)

    k_i = b"0"  # на первом шаге в хэш-функцию подается 0
    dkm = b""  # Derived Keying Material
    t = ceil(length / hash_len)

    # Второй шаг: с помощью хэш-функции вычисляем K(i), конкатенация которых
    # и является результатом работы функции. Заметим, что на каждом шаге
    # для вычисления K(i) используется предыдущее значение K(i-1):
    for i in range(t):
        k_i = hmac_sha256(prk, k_i + CTXinfo + bytes([1 + i]))
        dkm += k_i

    # Если длина не кратна hash_len, то возвращаются первые length октетов:
    return dkm[:length]

# output = hkdf(100, b"input_key", b"add_some_salt")
#
# print(''.join('{:02x}'.format(byte) for byte in output))
# print(len(out))